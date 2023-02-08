use crate::kms;
use crate::kms::Kms;
use crate::rand;
use aes_gcm::aead::AeadMutInPlace;
use alloc::format;
use alloc::string::String;
use alloc::string::ToString;
use alloc::sync::Arc;
use alloc::vec::Vec;
use chacha20poly1305::{
    aead::{Aead, AeadCore, KeyInit},
    ChaCha20Poly1305, Nonce,
};
use cipher::generic_array::sequence::GenericSequence;
use hashbrown::HashMap;
use serde::ser::SerializeStruct;
use serde::Deserialize;
use serde::Serialize;
use serde_json::Value;
use zeroize::ZeroizeOnDrop;

pub(crate) const KEY_ID_LEN: usize = 4;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(try_from = "i8", into = "i8")]
#[repr(i8)]
pub enum KeyStatus {
    /// Indicates that the key is active and the primary key in the keyring. It
    /// will be used, by default, for encryption.
    ///
    /// The key will be used for decryption when aplicable (i.e. ciphertext
    /// encrypted with it).
    Primary = 0,
    /// The indicates that the key is active and can be used for encryption if
    /// specified.
    ///
    /// The key will be used for decryption when applicable (i.e. ciphertext
    /// encrypted with it).
    Secondary = 1,

    /// Indicates that the key is disabled and cannot be used for encryption
    /// except for [daead] queries. It can still be used to decrypt applicable
    /// ciphertext.
    Disabled = -1,
}

impl Default for KeyStatus {
    fn default() -> Self {
        Self::Secondary
    }
}
impl KeyStatus {
    /// Returns `true` if `Primary`.
    pub fn is_primary(&self) -> bool {
        *self == Self::Primary
    }
    pub fn is_secondary(&self) -> bool {
        *self == Self::Secondary
    }

    /// Returns `true` if `Disabled`.
    pub fn is_disabled(&self) -> bool {
        matches!(self, Self::Disabled)
    }
}

impl TryFrom<i8> for KeyStatus {
    type Error = String;
    fn try_from(i: i8) -> Result<Self, Self::Error> {
        match i {
            0 => Ok(Self::Primary),
            1 => Ok(Self::Secondary),
            -1 => Ok(Self::Disabled),
            _ => Err(format!("invalid key status: {}", i)),
        }
    }
}

impl From<KeyStatus> for i8 {
    fn from(s: KeyStatus) -> Self {
        s as i8
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
/// Metadata for a particular key.
pub struct KeyInfo<A> {
    id: u32,
    status: KeyStatus,
    algorithm: A,
}

pub(crate) trait KeyMaterial:
    Send + Sync + ZeroizeOnDrop + Clone + 'static + PartialEq + Eq
{
    type Algorithm: PartialEq + Eq;
    fn algorithm(&self) -> Self::Algorithm;
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct Key<M>
where
    M: KeyMaterial,
{
    id: u32,
    status: KeyStatus,
    material: M,
    meta: Option<Value>,
}
impl<M> Key<M>
where
    M: KeyMaterial,
{
    pub(crate) fn info(&self) -> KeyInfo<M::Algorithm>
    where
        M: KeyMaterial,
    {
        KeyInfo {
            id: self.id,
            status: self.status,
            algorithm: self.material.algorithm(),
        }
    }
}
impl<M> PartialEq for Key<M>
where
    M: KeyMaterial,
{
    fn eq(&self, other: &Self) -> bool {
        self.id == other.id
    }
}

#[derive(Clone, Debug)]
pub(crate) struct Keyring<M>
where
    M: KeyMaterial,
{
    keys: Vec<Arc<Key<M>>>,
    primary_key: Arc<Key<M>>,
    primary_key_id: u32,
    lookup: HashMap<u32, Arc<Key<M>>>,
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
        for key in keys {
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
                for key in keys {
                    if key.id == possible_corrective_id {
                        primary_key = Some(key.id);
                        break;
                    }
                }
            } else {
                for key in keys {
                    if key.id == possible_corrective_id {
                        key.status = KeyStatus::Secondary;
                        break;
                    }
                }
            }
        }
        if primary_key.is_none() {
            let last = keys.last_mut().unwrap();
            last.status = KeyStatus::Primary;
            primary_key_id = last.id;
        }

        let mut keyring = Vec::with_capacity(keys.len());
        let mut primary_key = None;
        for key in keys {
            let key = Arc::new(key);
            keyring.push(key.clone());
            lookup.insert(key.id, key);
            if primary_key_id == key.id {
                primary_key = Some(key.clone());
            }
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
        let key = Key {
            id,
            status: KeyStatus::Primary,
            material,
            meta: None,
        };
        let key = Arc::new(key);
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
    pub(crate) fn set_primary_key(&self, key: impl AsRef<u32>) -> Result<(), String> {
        let key = key.as_ref();
        let key = self.lookup.get(key).ok_or("key not found")?;
        let key = key.clone();
        self.primary_key = key;
        self.primary_key_id = key.id;
        Ok(())
    }

    pub(crate) fn keys(&self) -> &[Arc<Key<M>>] {
        &self.keys
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
    ) -> Result<Vec<u8>, String> {
        let key = ChaCha20Poly1305::generate_key(&mut crate::Random);
        let cipher = ChaCha20Poly1305::new(&key);
        let nonce = ChaCha20Poly1305::generate_nonce(&mut crate::Random);
        let mut serialized = serde_json::to_vec(self).map_err(|e| {
            format!("failed to serialize ciphertext\n\ncaused by:\n\t{}", e).to_string()
        })?;

        cipher
            .encrypt_in_place(&nonce, associated_data, &mut serialized)
            .map_err(|e| format!("failed to seal ciphertext\n\ncaused by:\n\t{}", e).to_string())?;

        let mut sealed = envelope
            .encrypt(&key, serialized.as_bytes())
            .await
            .map_err(|e| format!("failed to seal ciphertext\n\ncaused by:\n\t{}", e).to_string())?;
        todo!()
    }
}
// impl<'de, K> Deserialize<'de> for Keyring<Key<'de, K>> {
//     fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
//     where
//         K: Key,
//         D: serde::Deserializer<'de>,
//     {
//         let keys = Vec::<SecretKey>::deserialize(deserializer)?;
//         Keyring::new(keys).map_err(serde::de::Error::custom)
//     }
// }

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
