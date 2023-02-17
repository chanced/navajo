mod algorithm;
mod cipher;
mod ciphertext_info;
mod decryptor;
mod encryptor;
mod header;
mod key_info;
mod material;
mod method;
mod nonce;
mod seed;
mod segment;
mod size;
mod writer;
use alloc::vec::Vec;
pub use key_info::AeadKeyInfo;
use material::Material;
use size::Size;
use zeroize::ZeroizeOnDrop;

use crate::{
    error::{KeyNotFoundError, RemoveKeyError},
    key::{Key, KeyMaterial},
    keyring::Keyring,
    Buffer,
};
pub use algorithm::Algorithm;
pub use ciphertext_info::CiphertextInfo;

pub use decryptor::Decryptor;

pub use encryptor::Encryptor;
pub use method::Method;
pub use segment::Segment;
// use cipher::{ciphers, ring_ciphers, Cipher};

#[derive(Clone, Debug, ZeroizeOnDrop)]
pub struct Aead {
    keyring: Keyring<Material>,
}
impl Aead {
    pub fn new(algorithm: Algorithm, meta: Option<serde_json::Value>) -> Aead {
        Self {
            keyring: Keyring::new(Material::new(algorithm), crate::Origin::Generated, meta),
        }
    }

    pub fn add_key(&mut self, algorithm: Algorithm, meta: Option<serde_json::Value>) -> &mut Self {
        self.keyring
            .add(Material::new(algorithm), crate::Origin::Generated, meta);
        self
    }
    /// Returns [`AeadKeyInfo`] for the primary key.
    pub fn primary_key(&self) -> AeadKeyInfo {
        self.keyring.primary_key().into()
    }

    // fn primary_key_material(&self) -> &Key<Material> {
    //     self.keyring.primary_key()
    // }

    /// Returns a [`Vec`] containing [`AeadKeyInfo`] for each key in this
    /// keyring.
    pub fn keys(&self) -> Vec<AeadKeyInfo> {
        self.keyring.keys().iter().map(AeadKeyInfo::new).collect()
    }

    pub fn encrypt_in_place<B: Buffer>(
        &self,
        data: &mut B,
        aad: &[u8],
    ) -> Result<(), crate::error::EncryptError> {
        self.keyring.primary_key().encrypt_in_place(data, aad)
    }

    pub fn promote_key(
        &mut self,
        key_id: impl Into<u32>,
    ) -> Result<AeadKeyInfo, crate::error::KeyNotFoundError> {
        self.keyring.promote(key_id).map(AeadKeyInfo::new)
    }

    pub fn disable_key(
        &mut self,
        key_id: impl Into<u32>,
    ) -> Result<AeadKeyInfo, crate::error::DisableKeyError<Algorithm>> {
        self.keyring.disable(key_id).map(AeadKeyInfo::new)
    }

    pub fn enable_key(&mut self, key_id: impl Into<u32>) -> Result<AeadKeyInfo, KeyNotFoundError> {
        self.keyring.enable(key_id).map(AeadKeyInfo::new)
    }

    pub fn remove_key(
        &mut self,
        key_id: impl Into<u32>,
    ) -> Result<AeadKeyInfo, RemoveKeyError<Algorithm>> {
        self.keyring.remove(key_id).map(|k| AeadKeyInfo::new(&k))
    }

    pub fn update_key_meta(
        &mut self,
        key_id: impl Into<u32>,
        meta: Option<serde_json::Value>,
    ) -> Result<AeadKeyInfo, KeyNotFoundError> {
        self.keyring.update_meta(key_id, meta).map(AeadKeyInfo::new)
    }
}
