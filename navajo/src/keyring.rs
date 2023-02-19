use crate::error::DisableKeyError;
use crate::error::KeyNotFoundError;
use crate::error::OpenError;
use crate::error::RemoveKeyError;
use crate::error::SealError;
use crate::key::Key;
use crate::key::KeyMaterial;
use crate::kms::Kms;
use crate::rand;
use crate::Origin;
use crate::Status;

use aes_gcm::Aes256Gcm;
use alloc::format;
use alloc::string::ToString;
use alloc::vec;
use alloc::vec::Vec;
use chacha20poly1305::{
    aead::{AeadCore, KeyInit},
    ChaCha20Poly1305,
};
use hashbrown::HashMap;
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

const PRIMARY_KEY_NOT_FOUND_MSG:&str = "primary key not found in keyring\n\t\n\tthis is a bug. please report it to https://github.com/chanced/navajo/issues/new";

pub(crate) const KEY_ID_LEN: usize = 4;

#[derive(Clone, Debug, ZeroizeOnDrop)]
pub(crate) struct Keyring<M>
where
    M: KeyMaterial,
{
    keys: Vec<Key<M>>,
    primary_key_idx: usize,
    #[zeroize(skip)]
    lookup: HashMap<u32, usize>,
}
impl<Material> PartialEq for Keyring<Material>
where
    Material: KeyMaterial + PartialEq,
{
    fn eq(&self, other: &Self) -> bool {
        self.keys == other.keys
    }
}
impl<Material> Eq for Keyring<Material> where Material: KeyMaterial + Eq {}

impl<M> Serialize for Keyring<M>
where
    M: KeyMaterial + Serialize,
{
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        KeyringData {
            keys: self.keys.clone(),
            version: 0,
        }
        .serialize(serializer)
    }
}

impl<'de, Material> Deserialize<'de> for Keyring<Material>
where
    Material: KeyMaterial + Deserialize<'de>,
{
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let KeyringData::<Material> { mut keys, version } =
            KeyringData::<Material>::deserialize(deserializer)?;

        if version != 0 {
            return Err(serde::de::Error::custom(format!(
                "unsupported keyring version: {version}"
            )));
        }
        let mut lookup = HashMap::new();
        let mut primary_key_idx = None;
        for idx in 0..keys.len() {
            let key = &keys[idx];
            lookup.insert(key.id(), idx);
            if key.status().is_primary() {
                if let Some(former_primary) = primary_key_idx {
                    let k: &mut Key<Material> = keys.get_mut(former_primary).unwrap();
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
            keys,
            primary_key_idx,
            lookup,
        })
    }
}

impl<M> Keyring<M>
where
    M: KeyMaterial,
{
    pub(crate) fn new(material: M, origin: Origin, meta: Option<Value>) -> Self {
        let id = gen_id();
        let key = Key::new(id, Status::Primary, origin, material, meta);
        let mut lookup = HashMap::new();
        lookup.insert(id, 0);
        Self {
            keys: vec![key],
            lookup,
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
        let idx = self.lookup.remove(&id).ok_or(KeyNotFoundError(id))?;
        let key = self.keys.remove(idx);
        Ok(key)
    }

    pub(crate) fn get(&self, id: impl Into<u32>) -> Result<&Key<M>, KeyNotFoundError> {
        let id = id.into();
        self.lookup
            .get(&id)
            .and_then(|idx| self.keys.get(*idx))
            .ok_or(KeyNotFoundError(id))
    }
    pub(crate) fn get_mut(&mut self, id: impl Into<u32>) -> Result<&mut Key<M>, KeyNotFoundError> {
        let id = id.into();
        self.lookup
            .get(&id)
            .and_then(|idx| self.keys.get_mut(*idx))
            .ok_or(KeyNotFoundError(id))
    }

    pub(crate) fn get_mut_with_idx(
        &mut self,
        id: impl Into<u32>,
    ) -> Result<(usize, &mut Key<M>), KeyNotFoundError> {
        let id = id.into();
        let (idx, key) = self
            .lookup
            .get(&id)
            .map(|idx| (*idx, self.keys.get_mut(*idx)))
            .ok_or(KeyNotFoundError(id))?;
        key.ok_or(KeyNotFoundError(id)).map(|key| (idx, key))
    }

    pub(crate) fn add(&mut self, material: M, origin: Origin, meta: Option<Value>) -> &Key<M> {
        let id = self.gen_unique_id();
        let key = Key::new(id, Status::Secondary, origin, material, meta);
        self.keys.push(key);
        self.lookup.insert(id, self.keys.len() - 1);
        self.keys.last().unwrap()
    }

    pub(crate) fn update_meta(
        &mut self,
        id: impl Into<u32>,
        meta: Option<Value>,
    ) -> Result<&Key<M>, KeyNotFoundError> {
        self.get_mut(id).map(|key| key.update_meta(meta))
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
            .get(self.primary_key_idx)
            .expect(PRIMARY_KEY_NOT_FOUND_MSG)
    }
    pub(crate) fn primary_key_mut(&mut self) -> &mut Key<M> {
        self.keys
            .get_mut(self.primary_key_idx)
            .expect(PRIMARY_KEY_NOT_FOUND_MSG)
    }

    pub(crate) fn disable(
        &mut self,
        id: impl Into<u32>,
    ) -> Result<&Key<M>, DisableKeyError<M::Algorithm>> {
        let id = id.into();
        let primary_key_idx = self.primary_key_idx;
        let (idx, key) = self.get_mut_with_idx(id)?;
        if idx == primary_key_idx {
            return Err(DisableKeyError::IsPrimaryKey(key.info()));
        }
        key.disable()?;
        Ok(key)
    }

    pub(crate) fn enable(&mut self, id: impl Into<u32>) -> Result<&Key<M>, KeyNotFoundError> {
        let id = id.into();
        let key = self.get_mut(id)?;
        if key.status() != Status::Disabled {
            return Ok(key);
        }
        key.enable();
        Ok(key)
    }
    pub(crate) fn promote(&mut self, key: impl Into<u32>) -> Result<&Key<M>, KeyNotFoundError> {
        let id = key.into();
        if !self.lookup.contains_key(&id) {
            return Err(KeyNotFoundError(id));
        }
        self.primary_key_mut().demote();
        let idx = {
            let (idx, key) = self.get_mut_with_idx(id).unwrap();
            key.promote_to_primary();
            idx
        };
        self.primary_key_idx = idx;
        Ok(self.get(id).unwrap())
    }

    pub(crate) fn keys(&self) -> &[Key<M>] {
        &self.keys
    }

    fn gen_unique_id(&self) -> u32 {
        let mut id = gen_id();
        while self.lookup.contains_key(&id) {
            id = gen_id();
        }
        id
    }
}
impl<M> Keyring<M>
where
    M: KeyMaterial + Serialize,
{
    fn seal_first_pass(&self, associated_data: &[u8]) -> Result<Vec<u8>, SealError> {
        let mut serialized = serde_json::to_vec(self)?;
        use aes_gcm::aead::AeadInPlace;
        // Round 1: AES-256-GCM
        let key = Aes256Gcm::generate_key(&mut crate::Random);
        let mut cipher = Aes256Gcm::new(&key);
        let nonce = Aes256Gcm::generate_nonce(&mut crate::Random);
        serialized.reserve(AES_256_GCM_TAG_SIZE);
        cipher.encrypt_in_place(&nonce, associated_data, &mut serialized)?;
        let result = [key.as_slice(), nonce.as_slice(), serialized.as_slice()].concat();
        Ok(result)
    }

    fn seal_second_pass(
        &self,
        data: &mut Vec<u8>,
        associated_data: &[u8],
    ) -> Result<Vec<u8>, SealError> {
        let key = ChaCha20Poly1305::generate_key(&mut crate::Random);
        let mut cipher = ChaCha20Poly1305::new(&key);
        let nonce = ChaCha20Poly1305::generate_nonce(&mut crate::Random);
        use chacha20poly1305::aead::AeadInPlace;
        data.reserve(CHACHA20_POLY1305_TAG_SIZE);
        cipher.encrypt_in_place(&nonce, associated_data, data)?;
        let cipher_and_nonce = [key.as_slice(), nonce.as_slice()].concat();
        Ok(cipher_and_nonce)
    }

    fn serialize_and_seal_locally(
        &self,
        associated_data: &[u8],
    ) -> Result<(Vec<u8>, Vec<u8>), SealError> {
        let mut serialized_and_sealed = self.seal_first_pass(associated_data)?;
        let cipher_and_nonce =
            self.seal_second_pass(&mut serialized_and_sealed, associated_data)?;
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

    pub(crate) async fn seal(
        &self,
        associated_data: &[u8],
        kms: impl Kms,
    ) -> Result<Vec<u8>, SealError> {
        let (locally_serialized_and_sealed, cipher_and_nonce) =
            self.serialize_and_seal_locally(associated_data)?;

        let sealed_cipher_and_nonce = kms
            .encrypt(&cipher_and_nonce, associated_data)
            .await
            .map_err(|e| e.to_string())?;

        self.encode_serialized(
            &locally_serialized_and_sealed,
            &sealed_cipher_and_nonce,
            &cipher_and_nonce,
        )
    }
    pub(crate) fn seal_sync(
        &self,
        associated_data: &[u8],
        kms: impl Kms,
    ) -> Result<Vec<u8>, SealError> {
        let (locally_serialized_and_sealed, cipher_and_nonce) =
            self.serialize_and_seal_locally(associated_data)?;

        let sealed_cipher_and_nonce = kms
            .encrypt_sync(&cipher_and_nonce, associated_data)
            .map_err(|e| e.to_string())?;

        self.encode_serialized(
            &locally_serialized_and_sealed,
            &sealed_cipher_and_nonce,
            &cipher_and_nonce,
        )
    }
}

impl<M> Keyring<M>
where
    M: KeyMaterial + DeserializeOwned,
{
    pub(crate) async fn open<K>(
        sealed: &[u8],
        associated_data: &[u8],
        kms: K,
    ) -> Result<Self, OpenError>
    where
        K: Kms,
    {
        let sealed_cipher_and_nonce = Self::read_sealed_cipher_and_nonce(sealed)?;
        let key = kms
            .decrypt(sealed_cipher_and_nonce, associated_data)
            .await
            .map_err(|e| e.to_string())?;

        Self::open_and_deserialize(key, sealed, sealed_cipher_and_nonce, associated_data)
    }
    pub(crate) fn open_sync<K>(
        sealed: &[u8],
        associated_data: &[u8],
        kms: K,
    ) -> Result<Self, OpenError>
    where
        K: Kms,
    {
        let sealed_cipher_and_nonce = Self::read_sealed_cipher_and_nonce(sealed)?;
        let key = kms
            .decrypt_sync(sealed_cipher_and_nonce, associated_data)
            .map_err(|e| e.to_string())?;

        Self::open_and_deserialize(key, sealed, sealed_cipher_and_nonce, associated_data)
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

    fn read_sealed_cipher_and_nonce(sealed: &[u8]) -> Result<&[u8], OpenError> {
        let sealed_cipher_and_nonce_len = Self::read_sealed_cipher_nonce_len(sealed)?;
        let sealed_cipher_and_nonce = &sealed[4..4 + sealed_cipher_and_nonce_len];
        Ok(sealed_cipher_and_nonce)
    }

    fn open_first_pass(
        mut key: Vec<u8>,
        buffer: &mut Vec<u8>,
        associated_data: &[u8],
    ) -> Result<usize, OpenError> {
        use chacha20poly1305::aead::AeadInPlace;
        if key.len() != CHACHA20_POLY1305_KEY_SIZE + CHACHA20_POLY1305_NONCE_SIZE {
            return Err("kms returned invalid data".into());
        }
        let nonce = key.split_off(CHACHA20_POLY1305_KEY_SIZE);
        let nonce = chacha20poly1305::Nonce::from_slice(&nonce);

        let mut cipher = ChaCha20Poly1305::new_from_slice(&key)?;
        cipher.decrypt_in_place(nonce, associated_data, buffer)?;
        Ok(nonce.len() + key.len())
    }

    fn open_second_pass(buffer: &mut Vec<u8>, associated_data: &[u8]) -> Result<(), OpenError> {
        use aes_gcm::aead::AeadInPlace;
        let mut data = buffer.split_off(AES_256_GCM_KEY_SIZE + AES_256_GCM_NONCE_SIZE);
        let nonce = buffer.split_off(AES_256_GCM_KEY_SIZE);
        let nonce = aes_gcm::Nonce::from_slice(&nonce);
        let mut cipher = Aes256Gcm::new_from_slice(buffer)?;
        cipher.decrypt_in_place(nonce, associated_data, &mut data)?;
        *buffer = data;
        Ok(())
    }
    fn open_and_deserialize(
        key: Vec<u8>,
        sealed: &[u8],
        sealed_cipher_and_nonce: &[u8],
        associated_data: &[u8],
    ) -> Result<Self, OpenError> {
        let mut buffer = sealed[4 + sealed_cipher_and_nonce.len()..].to_vec();
        Self::open_first_pass(key, &mut buffer, associated_data)?;
        Self::open_second_pass(&mut buffer, associated_data)?;
        let result: Keyring<M> = serde_json::from_slice(&buffer)?;
        Ok(result)
    }
}

pub(crate) fn gen_id() -> u32 {
    let mut data = [0; 4];
    rand::fill(&mut data);
    let mut value: u32 = u32::from_be_bytes(data);
    while value < 100_000_000 {
        rand::fill(&mut data);
        value = u32::from_be_bytes(data);
    }
    value
}

#[derive(Serialize, Deserialize)]
struct KeyringData<Material>
where
    Material: KeyMaterial,
{
    #[serde(rename = "v")]
    version: u32,
    #[serde(rename = "k")]
    keys: Vec<Key<Material>>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::key::test::Algorithm;
    use crate::key::test::Material;

    #[test]
    fn test_serde() {
        let material = Material::new(Algorithm::Waffles);
        let keyring = Keyring::new(material, Origin::Generated, Some("test".into()));
        let ser = serde_json::to_string(&keyring).unwrap();
        let de = serde_json::from_str::<Keyring<Material>>(&ser).unwrap();
        assert_eq!(keyring, de);
    }

    #[cfg(feature = "std")]
    #[tokio::test]
    async fn test_seal_and_open() {
        let material = Material::new(Algorithm::Waffles);
        let mut keyring = Keyring::new(material, Origin::Generated, Some("test".into()));
        keyring.add(Material::new(Algorithm::Cereal), Origin::Generated, None);
        let ser = serde_json::to_vec(&keyring).unwrap();
        let de = serde_json::from_slice::<Keyring<Material>>(&ser).unwrap();
        assert_eq!(keyring, de);

        let kms = crate::kms::InMemory::new();
        let sealed = keyring.seal(&[], kms.clone()).await.unwrap();
        assert_ne!(ser, sealed);
        let opened = Keyring::open(&sealed, &[], kms).await.unwrap();
        assert_eq!(keyring, opened);
    }

    #[test]
    fn test_key_status() {
        let material = Material::new(Algorithm::Pancakes);
        let mut keyring = Keyring::new(material, Origin::Generated, Some("test".into()));
        let first_id = {
            let first = keyring.primary();
            let first_id = first.id();
            assert_eq!(first.status(), Status::Primary);
            assert_eq!(first.meta_as_ref(), Some("test".into()).as_ref());
            assert_eq!(first.origin(), Origin::Generated);
            assert_ne!(first.id(), 0);
            assert_eq!(first.algorithm(), Algorithm::Pancakes);
            first_id
        };

        let second_id = {
            let second = keyring.add(Material::new(Algorithm::Waffles), Origin::Generated, None);
            assert_eq!(second.status(), Status::Secondary);
            assert_eq!(second.meta(), None);
            assert_eq!(second.origin(), Origin::Generated);
            assert_ne!(second.id(), 0);
            second.id()
        };
        {
            let second = keyring.get(second_id).unwrap();
            assert_eq!(second.status(), Status::Secondary);
            assert_eq!(second.origin(), Origin::Generated);
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
