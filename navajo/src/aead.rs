mod algorithm;
mod cipher;
mod ciphertext_info;
mod decryptor;
mod encryptor;
mod key_info;
mod material;
mod method;
mod nonce;
mod seed;
mod segment;
mod size;
mod stream;
mod try_stream;
mod writer;

use alloc::vec::Vec;
use core::mem;
use material::Material;
use size::Size;
use zeroize::ZeroizeOnDrop;

use crate::{
    error::{EncryptError, KeyNotFoundError, RemoveKeyError},
    keyring::Keyring,
    Buffer,
};

pub use algorithm::Algorithm;
pub use ciphertext_info::CiphertextInfo;
pub use decryptor::Decryptor;
pub use encryptor::Encryptor;
pub use key_info::AeadKeyInfo;
pub use method::Method;
pub use segment::Segment;
pub use stream::{AeadStream, DecryptStream, EncryptStream};
// pub use try_stream::{AeadTryStream, TryDecryptStream, TryEncryptStream};

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

    /// Returns a [`Vec`] containing [`AeadKeyInfo`] for each key in this
    /// keyring.
    pub fn keys(&self) -> Vec<AeadKeyInfo> {
        self.keyring.keys().iter().map(AeadKeyInfo::new).collect()
    }

    pub fn encrypt_in_place<B: Buffer>(
        &self,
        additional_data: &[u8],
        data: &mut B,
    ) -> Result<(), EncryptError> {
        let encryptor = Encryptor::new(self, None, mem::take(data));
        let result = encryptor
            .finalize(additional_data)?
            .next()
            .ok_or(EncryptError::Unspecified)?;
        *data = result;
        Ok(())
    }

    pub fn decrypt_in_place<B: Buffer>(
        &self,
        additional_data: &[u8],
        data: &mut B,
    ) -> Result<(), crate::error::DecryptError> {
        let decryptor = Decryptor::new(self, mem::take(data));
        let result = decryptor
            .finalize(additional_data)?
            .next()
            .ok_or(crate::error::DecryptError::Unspecified)?;
        *data = result;
        Ok(())
    }
    pub fn encrypt(&self, additional_data: &[u8], data: &[u8]) -> Result<Vec<u8>, EncryptError> {
        let data = data.to_vec();
        let encryptor = Encryptor::new(self, None, data);
        let mut result = Vec::new();
        for segment in encryptor.finalize(additional_data)? {
            result.extend_from_slice(&segment);
        }
        Ok(result)
    }
    pub fn decrypt(
        &self,
        additional_data: &[u8],
        data: &[u8],
    ) -> Result<Vec<u8>, crate::error::DecryptError> {
        let data = data.to_vec();
        let decryptor = Decryptor::new(self, data);
        let mut result = Vec::new();
        for segment in decryptor.finalize(additional_data)? {
            result.extend_from_slice(&segment);
        }
        Ok(result)
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
impl AsRef<Aead> for Aead {
    fn as_ref(&self) -> &Aead {
        self
    }
}

impl AsMut<Aead> for Aead {
    fn as_mut(&mut self) -> &mut Aead {
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encrypt_in_place() {
        let aead = Aead::new(Algorithm::Aes256Gcm, None);
        let mut data = b"hello world".to_vec();
        aead.encrypt_in_place(b"additional data", &mut data)
            .unwrap();
        assert_ne!(data, b"hello world");
        assert!(!data.is_empty());
    }
    #[test]
    fn test_decrypt_in_place() {
        let aead = Aead::new(Algorithm::Aes256Gcm, None);
        let mut data = b"hello world".to_vec();
        aead.encrypt_in_place(b"additional data", &mut data)
            .unwrap();
        let aead = Aead::new(Algorithm::Aes256Gcm, None);
        let mut data = b"hello world".to_vec();
        aead.encrypt_in_place(b"additional data", &mut data)
            .unwrap();
        assert_ne!(data, b"hello world");
        aead.decrypt_in_place(b"additional data", &mut data)
            .unwrap();
        assert_eq!(data, b"hello world");
    }
}
