use crate::error::OpenError;
use crate::error::SealError;
use crate::key::Key;
use crate::key::KeyMaterial;
use crate::kms;
use crate::kms::Kms;
use crate::rand;
use crate::KeyStatus;
use aes_gcm::aead::AeadMutInPlace;
use alloc::format;
use alloc::string::String;
use alloc::string::ToString;
use alloc::sync::Arc;
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

pub(crate) const KEY_ID_LEN: usize = 4;

#[derive(Clone, Debug)]
pub(crate) struct Keyring<M>
where
    M: KeyMaterial,
{
    keys: Vec<Key<M>>,
    primary_key_id: u32,
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
        state.serialize_field("primary_key_id", &self.primary_key_id)?;
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
        let KeyringData {
            mut keys,
            mut primary_key_id,
        } = KeyringData::deserialize(deserializer)?;

        let mut lookup: HashMap<u32, Arc<Key<Material>>> = HashMap::new();
        // this is a safeguard that should never have to be used.
        let mut corrective_primary_key_id = None;
        let mut primary_key = None;
        if keys.len() == 0 {
            return Err(serde::de::Error::custom("empty keyring"));
        }
        for key in keys.iter() {
            if lookup.contains_key(&key.id) {
                if key.material == lookup[&key.id].material {
                    lookup.remove(&key.id);
                } else {
                    return Err(serde::de::Error::custom(format!(
                        "duplicate key id: {}",
                        key.id
                    )));
                }
            }
            if key.id == primary_key_id {
                primary_key = Some(key.id);
            } else if key.status == KeyStatus::Primary {
                corrective_primary_key_id = Some(key.id);
            }
        }
        if let Some(possible_corrective_id) = Some(primary_key_id) {
            if primary_key == None {
                for key in keys.iter() {
                    if key.id == possible_corrective_id {
                        primary_key = Some(key.id);
                        break;
                    }
                }
            } else {
                for mut key in keys.iter_mut() {
                    if key.id == possible_corrective_id {
                        key.status = KeyStatus::Secondary;
                        break;
                    }
                }
            }
        }
        if primary_key.is_none() {
            if let Some(new_pk_id) = corrective_primary_key_id.take() {
                primary_key_id = new_pk_id;
                for mut key in keys.iter_mut() {
                    if key.id == new_pk_id {
                        key.status = KeyStatus::Primary;
                        break;
                    }
                }
            } else {
                let last = keys.last_mut().unwrap();
                last.status = KeyStatus::Primary;
                primary_key_id = last.id;
            }
        }

        if let Some(invalid_key_id) = corrective_primary_key_id {
            for mut key in keys.iter_mut() {
                if key.id == invalid_key_id {
                    key.status = KeyStatus::Secondary;
                    break;
                }
            }
        }

        let mut keyring = Vec::with_capacity(keys.len());
        let mut primary_key = None;
        for key in keys {
            let key = Arc::new(key);
            keyring.push(key.clone());
            if primary_key_id == key.id {
                primary_key = Some(key.clone());
            }
            lookup.insert(key.id, key);
        }
        Ok(Self {
            keys: keyring,
            primary_key: primary_key.unwrap(),
            primary_key_id,
            lookup,
        })
    }
}

impl<M> Keyring<M>
where
    M: KeyMaterial,
{
    pub(crate) fn new(material: M, meta: Option<Value>) -> Self {
        let id = gen_id();
        let key = Key::new(id, KeyStatus::Primary, material, meta);

        let key = key;
        let mut keys = Vec::new();
        keys.push(key.clone());
        let mut lookup = HashMap::new();
        lookup.insert(id, key.clone());
        Self {
            keys,
            primary_key: key.clone(),
            primary_key_id: id,
            lookup,
        }
    }
    pub(crate) fn add(&mut self, material: M) -> u32 {
        let id = self.gen_unique_id();
        let key = Key {
            id,
            status: KeyStatus::Secondary,
            material,
            meta: None,
        };
        let key = Arc::new(key);
        self.keys.push(key.clone());
        self.lookup.insert(id, key.clone());
        id
    }
    pub(crate) fn update_meta(&mut self, id: impl AsRef<u32>, meta: Option<Value>) {
        let id = id.as_ref();
        let key = self.lookup.get_mut(id).unwrap();
        key.meta = meta;
    }
    pub(crate) fn remove(&mut self, id: impl AsRef<u32>) -> Result<(), String> {
        let id = id.as_ref();
        if *id == self.primary_key_id {
            return Err("cannot remove primary key".to_string());
        }
        let key = self.lookup.remove(id).ok_or("key not found")?;
        self.keys.retain(|k| !Arc::ptr_eq(k, &key));
        Ok(())
    }

    pub(crate) fn get(&self, id: impl AsRef<u32>) -> Option<Arc<Key<M>>> {
        self.lookup.get(id.as_ref()).cloned()
    }
    pub(crate) fn primary_key(&self) -> Arc<Key<M>> {
        self.primary_key.clone()
    }
    pub(crate) fn primary_key_info(&self) -> Arc<Key<M>> {
        self.primary_key.clone()
    }
    pub(crate) fn set_primary_key(&mut self, key: impl AsRef<u32>) -> Result<(), String> {
        let key = key.as_ref();
        let key = self.lookup.get(key).ok_or("key not found")?;
        let key = key.clone();
        self.primary_key = key;
        self.primary_key_id = key.id;
        Ok(())
    }

    pub(crate) fn keys(&self) -> impl Iterator<Item = Arc<Key<M>>> + '_ {
        self.keys.iter().cloned()
    }
    pub(crate) fn gen_unique_id(&self) -> u32 {
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
        let key = ChaCha20Poly1305::generate_key(&mut crate::Random);
        let mut cipher = ChaCha20Poly1305::new(&key);
        let nonce = ChaCha20Poly1305::generate_nonce(&mut crate::Random);
        let mut serialized = serde_json::to_vec(self)?;

        let mut cipher_and_nonce = key.to_vec();
        cipher_and_nonce.extend_from_slice(&nonce);

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
        cipher.encrypt_in_place(&nonce, associated_data, &mut serialized)?;
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

        // let result: Keyring<M> = serde_json::from_slice(&buffer)?;
        // Ok(result)
        todo!()
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
