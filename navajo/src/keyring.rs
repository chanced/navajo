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
use aes_gcm::aead::AeadMutInPlace;
use aes_gcm::Aes256Gcm;
use alloc::string::ToString;
use alloc::vec;
use alloc::vec::Vec;
use chacha20poly1305::{
    aead::{AeadCore, KeyInit},
    ChaCha20Poly1305,
};
use hashbrown::HashMap;
use serde::ser::SerializeStruct;
use serde::Deserialize;
use serde::Serialize;
use serde_json::Value;

const CHACHA20_POLY1305_KEY_SIZE: usize = 32;
const CHACHA20_POLY1305_NONCE_SIZE: usize = 12;
const CHACHA20_POLY1305_TAG_SIZE: usize = 16;

const AES_256_GCM_KEY_SIZE: usize = 32;
const AES_256_GCM_NONCE_SIZE: usize = 12;
const AES_256_GCM_TAG_SIZE: usize = 16;

const PRIMARY_KEY_NOT_FOUND_MSG:&str = "primary key not found in keyring\n\nthis is a bug. please report it to https://github.com/chanced/navajo/issues/new";

pub(crate) const KEY_ID_LEN: usize = 4;

#[derive(Clone, Debug)]
pub(crate) struct Keyring<M>
where
    M: KeyMaterial,
{
    keys: Vec<Key<M>>,
    primary_key_idx: usize,
    lookup: HashMap<u32, usize>,
}
impl<M> Serialize for Keyring<M>
where
    M: KeyMaterial + Serialize,
{
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut state = serializer.serialize_struct("Keyring", 2)?;
        state.serialize_field("keys", &self.keys)?;
        state.end()
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
        // let KeyringData {
        //     mut keys,
        //     mut primary_key_id,
        // } = KeyringData::deserialize(deserializer)?;

        // let mut lookup: HashMap<u32, usize> = HashMap::new();
        // // this is a safeguard that should never have to be used.
        // let mut corrective_primary_key_id = None;
        // let mut primary_key = None;
        // if keys.len() == 0 {
        //     return Err(serde::de::Error::custom("empty keyring"));
        // }
        // for key in keys.iter() {
        //     if lookup.contains_key(&key.id) {
        //         if key.material == lookup[&key.id].material {
        //             lookup.remove(&key.id);
        //         } else {
        //             return Err(serde::de::Error::custom(format!(
        //                 "duplicate key id: {}",
        //                 key.id
        //             )));
        //         }
        //     }
        //     if key.id == primary_key_id {
        //         primary_key = Some(key.id);
        //     } else if key.status == KeyStatus::Primary {
        //         corrective_primary_key_id = Some(key.id);
        //     }
        // }
        // if let Some(possible_corrective_id) = Some(primary_key_id) {
        //     if primary_key == None {
        //         for key in keys.iter() {
        //             if key.id == possible_corrective_id {
        //                 primary_key = Some(key.id);
        //                 break;
        //             }
        //         }
        //     } else {
        //         for mut key in keys.iter_mut() {
        //             if key.id == possible_corrective_id {
        //                 key.status = KeyStatus::Secondary;
        //                 break;
        //             }
        //         }
        //     }
        // }
        // if primary_key.is_none() {
        //     if let Some(new_pk_id) = corrective_primary_key_id.take() {
        //         primary_key_id = new_pk_id;
        //         for mut key in keys.iter_mut() {
        //             if key.id == new_pk_id {
        //                 key.status = KeyStatus::Primary;
        //                 break;
        //             }
        //         }
        //     } else {
        //         let last = keys.last_mut().unwrap();
        //         last.status = KeyStatus::Primary;
        //         primary_key_id = last.id;
        //     }
        // }

        // if let Some(invalid_key_id) = corrective_primary_key_id {
        //     for mut key in keys.iter_mut() {
        //         if key.id == invalid_key_id {
        //             key.status = KeyStatus::Secondary;
        //             break;
        //         }
        //     }
        // }

        // let mut keyring = Vec::with_capacity(keys.len());
        // let mut primary_key = None;
        // for key in keys {
        //     keyring.push(key.clone());
        //     if primary_key_id == key.id {
        //         primary_key = Some(key.clone());
        //     }
        //     lookup.insert(key.id, key.id);
        // }
        // Ok(Self {
        //     keys: keyring,
        //     primary_key: primary_key.unwrap(),
        //     primary_key_id,
        //     lookup,
        // })
        todo!()
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
        let primary_key = self.primary_key();
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

    pub(crate) fn add(&mut self, origin: Origin, material: M, meta: Option<Value>) -> &Key<M> {
        let id = self.gen_unique_id();
        let key = Key::new(id, Status::Secondary, origin, material, meta);
        self.keys.push(key);
        self.lookup.insert(id, self.keys.len() - 1);
        self.keys.last().unwrap()
    }

    pub(crate) fn update_meta(
        &mut self,
        id: impl AsRef<u32>,
        meta: Option<Value>,
    ) -> Result<&Key<M>, KeyNotFoundError> {
        let id = id.as_ref();
        if let Some(key_id) = self.lookup.get(id) {
            let key = &mut self.keys[*key_id];
            key.update_meta(meta);
            Ok(key)
        } else {
            Err(KeyNotFoundError(*id))
        }
    }

    pub(crate) fn primary_key(&self) -> &Key<M> {
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
            return Err(DisableKeyError::IsPrimaryKey(key.info().into()));
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
    pub(crate) async fn seal(
        &self,
        associated_data: &[u8],
        envelope: impl Kms,
    ) -> Result<Vec<u8>, SealError> {
        let mut serialized = serde_json::to_vec(self)?;

        let key = Aes256Gcm::generate_key(&mut crate::Random);
        let mut cipher = Aes256Gcm::new(&key);
        let nonce = ChaCha20Poly1305::generate_nonce(&mut crate::Random);
        serialized.reserve(AES_256_GCM_TAG_SIZE);
        cipher.encrypt_in_place(&nonce, associated_data, &mut serialized);

        let key = ChaCha20Poly1305::generate_key(&mut crate::Random);
        let mut cipher = ChaCha20Poly1305::new(&key);
        let nonce = ChaCha20Poly1305::generate_nonce(&mut crate::Random);
        serialized.reserve(CHACHA20_POLY1305_TAG_SIZE);
        cipher.encrypt_in_place(&nonce, associated_data, &mut serialized);

        let cipher_and_nonce = [key.as_slice(), nonce.as_slice()].concat();

        let sealed_cipher_and_nonce = envelope
            .encrypt(&key, &associated_data)
            .await
            .map_err(|e| e.to_string())?;
        let sealed_len: u32 = sealed_cipher_and_nonce
            .len()
            .try_into()
            .map_err(|_| "result from kms too long".to_string())?;

        if sealed_cipher_and_nonce.len() >= key.len() {
            if sealed_cipher_and_nonce[0..key.len()] == key[..] {
                return Err("kms failed to seal".into());
            }
            if sealed_cipher_and_nonce[sealed_cipher_and_nonce.len() - key.len()..] == key[..] {
                return Err("kms failed to seal".into());
            }
        }
        let mut result = sealed_len.to_be_bytes().to_vec();

        result.extend_from_slice(&sealed_cipher_and_nonce);
        result.extend_from_slice(&serialized);
        Ok(result)
    }
}

impl<'de, M> Keyring<M>
where
    M: KeyMaterial + Deserialize<'de>,
{
    pub(crate) async fn open(
        sealed: &[u8],
        associated_data: &[u8],
        envelope: impl Kms,
    ) -> Result<Self, OpenError> {
        if sealed.len() < 4 {
            return Err("sealed data too short".into());
        }

        let sealed_cipher_and_nonce_len = u32::from_be_bytes(sealed[0..4].try_into().unwrap()); // safe: len checked above.

        if sealed.len() < 4 + sealed_cipher_and_nonce_len as usize {
            return Err("sealed data too short".into());
        }

        let sealed_cipher_and_nonce = &sealed[4..4 + sealed_cipher_and_nonce_len as usize];
        let mut key = envelope
            .decrypt(sealed_cipher_and_nonce, &associated_data)
            .await
            .map_err(|e| e.to_string())?;

        if key.len() != CHACHA20_POLY1305_KEY_SIZE + CHACHA20_POLY1305_NONCE_SIZE {
            return Err("kms returned invalid data".into());
        }
        let nonce = key.split_off(CHACHA20_POLY1305_KEY_SIZE);
        let nonce = chacha20poly1305::Nonce::from_slice(&nonce);
        let mut buffer = sealed[4 + sealed_cipher_and_nonce_len as usize..].to_vec();
        let mut cipher = ChaCha20Poly1305::new_from_slice(&key)?;
        cipher.decrypt_in_place(&nonce, associated_data, &mut buffer)?;
        buffer.split_off(buffer.len() - CHACHA20_POLY1305_TAG_SIZE);

        let key = buffer[0..AES_256_GCM_KEY_SIZE].to_vec();
        let nonce =
            buffer[AES_256_GCM_KEY_SIZE..AES_256_GCM_KEY_SIZE + AES_256_GCM_NONCE_SIZE].to_vec();
        let mut buffer = buffer[AES_256_GCM_KEY_SIZE + AES_256_GCM_NONCE_SIZE..].to_vec();
        let mut cipher = Aes256Gcm::new_from_slice(&key)?;
        let nonce = aes_gcm::Nonce::from_slice(&nonce);
        cipher.decrypt_in_place(&nonce, associated_data, &mut buffer)?;
        _ = buffer.split_off(buffer.len() - AES_256_GCM_TAG_SIZE);
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

#[derive(Deserialize)]
struct KeyringData<Material>
where
    Material: KeyMaterial,
{
    keys: Vec<Key<Material>>,
    primary_key_id: u32,
}
