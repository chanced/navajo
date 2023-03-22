use core::ops::Deref;
use core::ops::Index;

use crate::envelope::Envelope;
use crate::error::DisableKeyError;
use crate::error::KeyNotFoundError;
use crate::error::OpenError;
use crate::error::RemoveKeyError;
use crate::error::SealError;
use crate::key::Key;
use crate::key::KeyMaterial;
use crate::primitive::Kind;
use crate::rand::Rng;
use crate::Aad;
use crate::Status;

use aes_gcm::Aes256Gcm;
use alloc::sync::Arc;
#[cfg(not(feature = "std"))]
use alloc::{format, string::String, vec, vec::Vec};
use chacha20poly1305::{
    aead::{AeadCore, KeyInit},
    ChaCha20Poly1305,
};
use serde::de::DeserializeOwned;
use serde::Deserialize;
use serde::Serialize;
use serde_json::Value;
use zeroize::ZeroizeOnDrop;
const CHACHA20_POLY1305_KEY_SIZE: usize = 32;
const CHACHA20_POLY1305_NONCE_SIZE: usize = 12;
const CHACHA20_POLY1305_TAG_SIZE: usize = 16;

const AES_256_GCM_KEY_SIZE: usize = 32;
const AES_256_GCM_NONCE_SIZE: usize = 12;
const AES_256_GCM_TAG_SIZE: usize = 16;

const PRIMARY_KEY_NOT_FOUND_MSG: &str =
    "primary key not found in keyring\n\t\n\tthis is a bug. please report it to {NEW_ISSUE_URL}";

pub(crate) const KEY_ID_LEN: usize = 4;

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Keys<M>(Arc<[Key<M>]>)
where
    M: KeyMaterial;

impl<M, R> From<R> for Keys<M>
where
    M: KeyMaterial,
    R: AsRef<[Key<M>]>,
{
    fn from(r: R) -> Self {
        Self(Arc::from(r.as_ref()))
    }
}
impl<M> PartialEq for Keys<M>
where
    M: KeyMaterial,
{
    fn eq(&self, other: &Self) -> bool {
        self.0.iter().eq(other.0.iter())
    }
}

impl<M> Keys<M>
where
    M: KeyMaterial,
{
    // fn len(&self) -> usize {
    //     self.0.len()
    // }
    fn get(&self, id: u32) -> Option<(usize, &Key<M>)> {
        self.position(id).map(|idx| (idx, &self.0[idx]))
    }
    fn get_by_idx(&self, idx: usize) -> Option<&Key<M>> {
        self.0.get(idx)
    }
    fn position(&self, id: u32) -> Option<usize> {
        self.0.iter().position(|k| k.id() == id)
    }
    fn push(&mut self, key: Key<M>) -> &Key<M> {
        let mut keys = self.0.iter().cloned().collect::<Vec<_>>();
        keys.push(key);
        self.0 = Arc::from(keys);
        self.0.last().unwrap()
    }
    fn remove(&mut self, id: u32) -> Result<Key<M>, KeyNotFoundError> {
        let idx = self.position(id).ok_or(KeyNotFoundError(id))?;
        let mut keys = self.0.iter().cloned().collect::<Vec<_>>();
        let key = keys.remove(idx);
        self.0 = Arc::from(keys);
        Ok(key)
    }
    fn iter(&self) -> impl Iterator<Item = &Key<M>> {
        self.0.iter()
    }
    fn update(&mut self, key: Key<M>) -> Result<&Key<M>, KeyNotFoundError> {
        let idx = self.position(key.id()).ok_or(KeyNotFoundError(key.id()))?;
        let mut keys = self.0.iter().cloned().collect::<Vec<_>>();
        keys[idx] = key;
        self.0 = Arc::from(keys);
        Ok(&self.0[idx])
    }
    // fn demote(&mut self, id: u32) -> Result<&Key<M>, KeyNotFoundError> {
    //     let idx = self.position(id).ok_or(KeyNotFoundError(id))?;
    //     let mut keys = self.0.iter().cloned().collect::<Vec<_>>();
    //     let key = keys.get_mut(idx).unwrap();
    //     key.demote();
    //     self.0 = Arc::from(keys);
    //     Ok(&self.0[idx])
    // }
}
impl<M> Deref for Keys<M>
where
    M: KeyMaterial,
{
    type Target = [Key<M>];

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}
impl<Material> ZeroizeOnDrop for Keys<Material> where Material: KeyMaterial {}
impl<Material> Index<usize> for Keys<Material>
where
    Material: KeyMaterial,
{
    type Output = Key<Material>;

    fn index(&self, index: usize) -> &Self::Output {
        &self.0[index]
    }
}

#[derive(Clone, Debug, Serialize)]
pub(crate) struct Keyring<M>
where
    M: KeyMaterial,
{
    version: u8,
    keys: Keys<M>,
    #[serde(skip_serializing)]
    primary_key_idx: usize,
}

impl<M> PartialEq for Keyring<M>
where
    M: KeyMaterial + PartialEq,
{
    fn eq(&self, other: &Self) -> bool {
        self.keys == other.keys
    }
}

impl<Material> Eq for Keyring<Material> where Material: KeyMaterial + Eq {}

#[derive(Serialize, Deserialize)]
struct KeyringData<M>
where
    M: KeyMaterial,
{
    #[serde(alias = "v")]
    version: u32,
    #[serde(alias = "m")]
    keys: Vec<Key<M>>,
}
impl<Material> ZeroizeOnDrop for Keyring<Material> where Material: KeyMaterial {}

impl<'de, M> Deserialize<'de> for Keyring<M>
where
    M: KeyMaterial + Deserialize<'de>,
{
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let KeyringData::<M> { mut keys, version } = KeyringData::<M>::deserialize(deserializer)?;

        if version != 0 {
            return Err(serde::de::Error::custom(format!(
                "unsupported keyring version: {version}"
            )));
        }
        let mut primary_key_idx = None;
        for idx in 0..keys.len() {
            let key = &keys[idx];
            if key.status().is_primary() {
                if let Some(former_primary) = primary_key_idx {
                    let k: &mut Key<M> = keys.get_mut(former_primary).unwrap();
                    k.demote();
                }
                primary_key_idx = Some(idx);
            }
        }
        let primary_key_idx = if let Some(primary_key_idx) = primary_key_idx {
            primary_key_idx
        } else {
            // something went sideways. we should definitely have a primary key at this point.
            // for now, this is going to select the last key. this is not ideal, but it's better
            // than locking up a keyring.
            //
            // if the key went poof, some data will not be retainable or verifiable.
            //
            // theoretically, this should never happen.
            //
            // todo: revisit this. Should it panic? Should there be logging and alert?
            // logging has been omitted due to concerns over security but it may need to be added.
            keys.len() - 1
        };
        Ok(Self {
            version: 0,
            keys: Keys::from(keys),
            primary_key_idx,
        })
    }
}

impl<M> Keyring<M>
where
    M: KeyMaterial,
{
    pub(crate) fn new(key: Key<M>) -> Self {
        Self {
            version: 0,
            keys: [key].into(),
            primary_key_idx: 0,
        }
    }

    pub(crate) fn remove(
        &mut self,
        id: impl Into<u32>,
    ) -> Result<Key<M>, RemoveKeyError<M::Algorithm>> {
        let id = id.into();
        let primary_key = self.primary();
        if primary_key.id() == id {
            return Err(primary_key.info().into());
        }
        let key = self.keys.remove(id)?;
        Ok(key)
    }

    pub(crate) fn get(&self, id: impl Into<u32>) -> Result<&Key<M>, KeyNotFoundError> {
        let id = id.into();
        self.keys
            .get(id)
            .map(|(_, key)| key)
            .ok_or(KeyNotFoundError(id))
    }

    pub(crate) fn add(&mut self, key: Key<M>) {
        self.keys.push(key);
    }

    pub(crate) fn update_meta(
        &mut self,
        id: impl Into<u32>,
        meta: Option<Value>,
    ) -> Result<&Key<M>, KeyNotFoundError> {
        let mut key = self.get(id.into())?.clone();
        key.update_meta(meta);
        self.keys.update(key)
    }

    pub(crate) fn primary(&self) -> &Key<M> {
        // Safety: if this fails to locate the primary key, the keyring is in a
        // bad state. This would be a bug that needs to be resolved immediately.
        //
        // In the event that this does occur, restarting the application should,
        // at mimimum, partially resolve the issue. There is corrective logic in
        // place to ensure that if the primary key is not found, the last
        // created key becomes the primary. If this were a result of a
        // key-gone-missing scenario, then some data or messages may not be
        // recoverable.
        //
        // Panicing here rather than attempting to restore to ensure that the
        // user is aware of the corrupt state.
        self.keys
            .get_by_idx(self.primary_key_idx)
            .expect(PRIMARY_KEY_NOT_FOUND_MSG)
    }

    pub(crate) fn disable(
        &mut self,
        id: impl Into<u32>,
    ) -> Result<&Key<M>, DisableKeyError<M::Algorithm>> {
        let id = id.into();
        let primary = self.primary();
        if id == primary.id() {
            return Err(DisableKeyError::IsPrimaryKey(primary.info()));
        }
        let mut key = self.get(id)?.clone();
        key.disable()?;
        Ok(self.keys.update(key).unwrap())
    }

    pub(crate) fn enable(&mut self, id: impl Into<u32>) -> Result<&Key<M>, KeyNotFoundError> {
        let id = id.into();
        let mut key = self.get(id)?.clone();
        key.enable();
        self.keys.update(key)
    }

    // Returns the previous primary key
    pub(crate) fn promote(&mut self, id: impl Into<u32>) -> Result<&Key<M>, KeyNotFoundError> {
        let id = id.into();
        let (idx, mut key) = self
            .keys
            .get(id)
            .map(|(idx, key)| (idx, key.clone()))
            .ok_or(KeyNotFoundError(id))?;
        let prev_primary = self.primary_key_idx;
        if key.status() == Status::Primary {
            return Ok(self.keys.get_by_idx(prev_primary).unwrap());
        }
        let mut primary = self.primary().clone();

        primary.demote();
        key.promote();
        self.keys.update(key).unwrap();
        self.keys.update(primary).unwrap();
        self.primary_key_idx = idx;
        Ok(self.keys.get_by_idx(prev_primary).unwrap())
    }

    pub(crate) fn keys(&self) -> &[Key<M>] {
        &self.keys
    }

    pub(crate) fn next_id<G>(&self, rng: &G) -> u32
    where
        G: Rng,
    {
        let mut id = gen_id(rng);

        while self.keys.iter().any(|k| k.id() == id) {
            id = gen_id(rng);
        }
        id
    }
}

impl<M> Keyring<M>
where
    M: KeyMaterial + Serialize,
{
    fn serialize_for_sealing(&self) -> Result<Vec<u8>, SealError> {
        let material = serde_json::to_value(&self.keys).unwrap();
        let kind = serde_json::to_value(M::kind()).unwrap();
        let version = serde_json::to_value(self.version).unwrap();
        let result: Vec<u8>;
        #[cfg(feature = "std")]
        {
            let mut data = std::collections::HashMap::with_capacity(3);
            data.insert("k", kind);
            data.insert("v", version);
            data.insert("m", material);
            result = serde_json::to_vec(&data)?;
        }
        #[cfg(not(feature = "std"))]
        {
            let mut data = alloc::collections::BTreeMap::new();
            data.insert("k", kind);
            data.insert("v", version);
            data.insert("m", material);
            result = serde_json::to_vec(&data)?;
        }
        Ok(result)
    }

    fn seal_first_pass(&self, aad: &[u8]) -> Result<Vec<u8>, SealError> {
        let mut serialized = self.serialize_for_sealing()?;
        // serialized = lz4_flex::compress_prepend_size(&serialized);
        use aes_gcm::aead::AeadInPlace;
        // Round 1: AES-256-GCM
        let key = Aes256Gcm::generate_key(&mut crate::SystemRng);
        let cipher = Aes256Gcm::new(&key);
        let nonce = Aes256Gcm::generate_nonce(&mut crate::SystemRng);
        serialized.reserve(AES_256_GCM_TAG_SIZE);
        cipher.encrypt_in_place(&nonce, aad, &mut serialized)?;
        let result = [key.as_slice(), nonce.as_slice(), serialized.as_slice()].concat();
        Ok(result)
    }

    fn seal_second_pass(&self, data: &mut Vec<u8>, aad: &[u8]) -> Result<Vec<u8>, SealError> {
        let key = ChaCha20Poly1305::generate_key(&mut crate::SystemRng);
        let cipher = ChaCha20Poly1305::new(&key);
        let nonce = ChaCha20Poly1305::generate_nonce(&mut crate::SystemRng);
        use chacha20poly1305::aead::AeadInPlace;
        data.reserve(CHACHA20_POLY1305_TAG_SIZE);
        cipher.encrypt_in_place(&nonce, aad, data)?;
        let cipher_and_nonce = [key.as_slice(), nonce.as_slice()].concat();
        Ok(cipher_and_nonce)
    }

    fn serialize_and_seal_locally(&self, aad: &[u8]) -> Result<(Vec<u8>, Vec<u8>), SealError> {
        let mut serialized_and_sealed = self.seal_first_pass(aad)?;
        let cipher_and_nonce = self.seal_second_pass(&mut serialized_and_sealed, aad)?;
        Ok((serialized_and_sealed, cipher_and_nonce))
    }
    fn encode_serialized(
        &self,
        locally_serialized_and_sealed: &[u8],
        sealed_cipher_and_nonce: &[u8],
        key_and_nonce: &[u8],
    ) -> Result<Vec<u8>, SealError> {
        let sealed_len = sealed_cipher_and_nonce.len();

        if sealed_len >= key_and_nonce.len() {
            if sealed_cipher_and_nonce[0..key_and_nonce.len()] == key_and_nonce[..] {
                return Err("kms failed to seal".into());
            }
            if sealed_cipher_and_nonce[sealed_cipher_and_nonce.len() - key_and_nonce.len()..]
                == key_and_nonce[..]
            {
                return Err("kms failed to seal".into());
            }
        }

        let sealed_len = sealed_len as u32;
        let result = [
            sealed_len.to_be_bytes().as_slice(),
            sealed_cipher_and_nonce,
            locally_serialized_and_sealed,
        ]
        .concat();
        Ok(result)
    }

    pub(crate) async fn seal<A, E>(&self, aad: Aad<A>, envelope: &E) -> Result<Vec<u8>, SealError>
    where
        A: 'static + AsRef<[u8]> + Send + Sync,
        E: Envelope,
    {
        let (locally_serialized_and_sealed, cipher_and_nonce) =
            self.serialize_and_seal_locally(aad.as_ref())?;

        let sealed_cipher_and_nonce = envelope
            .encrypt_dek(aad, cipher_and_nonce.clone())
            .await
            .map_err(|e| e.to_string())?;

        self.encode_serialized(
            &locally_serialized_and_sealed,
            &sealed_cipher_and_nonce,
            &cipher_and_nonce,
        )
    }
    pub(crate) fn seal_sync<A, E>(&self, aad: Aad<A>, envelope: &E) -> Result<Vec<u8>, SealError>
    where
        A: AsRef<[u8]>,
        E: crate::envelope::sync::Envelope,
    {
        let (locally_serialized_and_sealed, cipher_and_nonce) =
            self.serialize_and_seal_locally(aad.as_ref())?;

        let sealed_cipher_and_nonce = envelope
            .encrypt_dek(aad, &cipher_and_nonce)
            .map_err(|e| e.to_string())?;

        self.encode_serialized(
            &locally_serialized_and_sealed,
            &sealed_cipher_and_nonce,
            &cipher_and_nonce,
        )
    }
}

pub(crate) async fn open_keyring_value<A, E>(
    aad: Aad<A>,
    ciphertext: Vec<u8>,
    envelope: &E,
) -> Result<(Kind, Value), OpenError>
where
    A: 'static + AsRef<[u8]>,
    E: Envelope,
{
    let sealed_cipher_and_nonce = read_sealed_cipher_and_nonce(&ciphertext)?;

    let key = envelope
        .decrypt_dek(Aad(aad.as_ref().to_vec()), sealed_cipher_and_nonce.clone())
        .await
        .map_err(|e| e.to_string())?;

    let value = open_and_deserialize(key, aad, &ciphertext, &sealed_cipher_and_nonce)?;
    let kind = get_kind(&value)?;
    Ok((kind, value))
}

pub(crate) fn open_keyring_value_sync<A, S, E>(
    aad: Aad<A>,
    sealed: S,
    envelope: &E,
) -> Result<(Kind, Value), OpenError>
where
    A: AsRef<[u8]>,
    S: AsRef<[u8]>,
    E: crate::envelope::sync::Envelope,
{
    let sealed = sealed.as_ref();
    let sealed_cipher_and_nonce = read_sealed_cipher_and_nonce(sealed)?;
    let key = envelope
        .decrypt_dek(Aad(aad.as_ref()), sealed_cipher_and_nonce.clone())
        .map_err(|e| e.to_string())?;

    let value = open_and_deserialize(key, aad, sealed, &sealed_cipher_and_nonce)?;
    let kind = get_kind(&value)?;
    Ok((kind, value))
}

fn get_kind(value: &Value) -> Result<Kind, OpenError> {
    let kind = value
        .get("k")
        .cloned()
        .ok_or("invalid keyring: missing kind")?;
    let kind: Kind = serde_json::from_value(kind)?;
    Ok(kind)
}

impl<M> Keyring<M> where M: KeyMaterial + DeserializeOwned {}

pub(crate) fn gen_id<G: Rng>(rng: &G) -> u32 {
    let mut value = rng.u32().unwrap();
    while value < 100_000_000 {
        value = rng.u32().unwrap();
    }
    value
}

fn read_sealed_cipher_nonce_len(sealed: &[u8]) -> Result<usize, OpenError> {
    if sealed.len() < 4 {
        return Err("sealed data too short".into());
    }
    let sealed_cipher_and_nonce_len = u32::from_be_bytes(sealed[0..4].try_into().unwrap()); // safe: len checked above.
    if sealed_cipher_and_nonce_len < 4 {
        return Err("sealed data too short".into());
    }
    let sealed_cipher_and_nonce_len: usize = sealed_cipher_and_nonce_len
        .try_into()
        .map_err(|_| OpenError("sealed data too long".into()))?;

    if sealed.len() < 4 + sealed_cipher_and_nonce_len {
        return Err("sealed data too short".into());
    }

    Ok(sealed_cipher_and_nonce_len)
}

fn read_sealed_cipher_and_nonce(sealed: &[u8]) -> Result<Vec<u8>, OpenError> {
    let sealed_cipher_and_nonce_len = read_sealed_cipher_nonce_len(sealed)?;
    let sealed_cipher_and_nonce = &sealed[4..4 + sealed_cipher_and_nonce_len];
    Ok(sealed_cipher_and_nonce.to_vec())
}

fn open_first_pass(mut key: Vec<u8>, buffer: &mut Vec<u8>, aad: &[u8]) -> Result<usize, OpenError> {
    use chacha20poly1305::aead::AeadInPlace;
    if key.len() != CHACHA20_POLY1305_KEY_SIZE + CHACHA20_POLY1305_NONCE_SIZE {
        return Err("kms returned invalid data".into());
    }
    let nonce = key.split_off(CHACHA20_POLY1305_KEY_SIZE);
    let nonce = chacha20poly1305::Nonce::from_slice(&nonce);
    let cipher = ChaCha20Poly1305::new_from_slice(&key)?;
    cipher.decrypt_in_place(nonce, aad, buffer)?;
    Ok(nonce.len() + key.len())
}

fn open_second_pass(buffer: &mut Vec<u8>, aad: &[u8]) -> Result<(), OpenError> {
    use aes_gcm::aead::AeadInPlace;
    let mut data = buffer.split_off(AES_256_GCM_KEY_SIZE + AES_256_GCM_NONCE_SIZE);
    let nonce = buffer.split_off(AES_256_GCM_KEY_SIZE);
    let nonce = aes_gcm::Nonce::from_slice(&nonce);
    let cipher = Aes256Gcm::new_from_slice(buffer)?;
    cipher.decrypt_in_place(nonce, aad, &mut data)?;
    *buffer = data;
    Ok(())
}
fn open_and_deserialize<A>(
    key: Vec<u8>,
    aad: Aad<A>,
    sealed: &[u8],
    sealed_cipher_and_nonce: &[u8],
) -> Result<Value, OpenError>
where
    A: AsRef<[u8]>,
{
    let mut buffer = sealed[4 + sealed_cipher_and_nonce.len()..].to_vec();
    open_first_pass(key, &mut buffer, aad.as_ref())?;
    open_second_pass(&mut buffer, aad.as_ref())?;
    // let buffer = lz4_flex::decompress_size_prepended(&buffer)
    //     .map_err(|e| "failed to decompress keyring: ".to_string() + e.to_string().as_str())?;
    let result: Value = serde_json::from_slice(&buffer)?;
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::key::test::Algorithm;
    use crate::key::test::Material;
    use crate::Origin;
    use crate::SystemRng;
    #[test]
    fn test_serde() {
        let rand = crate::rand::SystemRng::new(); // TODO: Replace with MockRandom.

        let material = Material::new(Algorithm::Waffles);
        let key = Key::new(
            0,
            Status::Primary,
            Origin::Navajo,
            material,
            Some("test".into()),
        );
        let keyring = Keyring::new(key);
        let ser = serde_json::to_string(&keyring).unwrap();
        let de = serde_json::from_str::<Keyring<Material>>(&ser).unwrap();
        assert_eq!(keyring, de);
    }

    #[cfg(feature = "std")]
    #[tokio::test]
    async fn test_seal_and_open() {
        use crate::rand::SystemRng;

        let rand = SystemRng::new(); // TODO: Replace with MockRandom.

        let material = Material::new(Algorithm::Waffles);
        let key = Key::new(
            0,
            Status::Primary,
            Origin::Navajo,
            material,
            Some("test".into()),
        );
        let mut keyring = Keyring::new(key);
        let second_key = Key::new(
            1,
            Status::Secondary,
            Origin::Navajo,
            Material::new(Algorithm::Cereal),
            Some("test".into()),
        );
        keyring.add(second_key);
        let ser = serde_json::to_vec(&keyring).unwrap();
        let de = serde_json::from_slice::<Keyring<Material>>(&ser).unwrap();
        assert_eq!(keyring, de);

        let in_mem = crate::envelope::InMemory::new();
        let sealed = keyring.seal(Aad(&[]), &in_mem).await.unwrap();
        assert_ne!(ser, sealed);
        let (kind, opened) = open_keyring_value(Aad(&[]), sealed.clone(), &in_mem)
            .await
            .unwrap();
        assert_eq!(kind, Kind::Aead);
        let opened = serde_json::from_value(opened).unwrap();
        assert_eq!(keyring, opened);
    }

    #[test]
    fn test_key_status() {
        let rng = SystemRng;
        let material = Material::new(Algorithm::Pancakes);
        let key = Key::new(
            rng.u32().unwrap(),
            Status::Primary,
            Origin::Navajo,
            material,
            Some("test".into()),
        );
        let mut keyring = Keyring::new(key);

        let first_id = {
            let first = keyring.primary();
            let first_id = first.id();
            assert_eq!(first.status(), Status::Primary);
            assert_eq!(first.meta().as_deref(), Some("test".into()).as_ref());
            assert_eq!(first.origin(), Origin::Navajo);
            assert_eq!(first.algorithm(), Algorithm::Pancakes);
            first_id
        };

        let second_id = keyring.next_id(&SystemRng);
        let second_material = Material::new(Algorithm::Waffles);
        let second_key = Key::new(
            second_id,
            Status::Secondary,
            Origin::Navajo,
            second_material,
            None,
        );
        keyring.add(second_key);
        {
            let second = keyring.get(second_id).unwrap();
            assert_eq!(second.status(), Status::Secondary);
            assert_eq!(second.origin(), Origin::Navajo);
            assert_eq!(second.id(), second_id);
            keyring.promote(second.id()).unwrap();
        }
        {
            let primary = keyring.primary();
            assert_eq!(primary.status(), Status::Primary);
            assert_eq!(primary.id(), second_id);
        }
        {
            let first = keyring.get(first_id).unwrap();
            assert_eq!(first.status(), Status::Secondary);
        }

        assert!(keyring.remove(second_id).is_err());
        assert!(keyring.disable(second_id).is_err());
        assert!(keyring.remove(first_id).is_ok());
    }
}
