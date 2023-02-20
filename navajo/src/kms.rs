use core::{fmt::Display, pin::Pin};

use aes_gcm::{aead::Aead, AeadCore};
use alloc::{borrow::ToOwned, boxed::Box, vec::Vec};
use chacha20poly1305::{aead::Payload, ChaCha20Poly1305, KeyInit};

use futures::Future;
#[allow(clippy::type_complexity)]
pub trait Kms {
    type EncryptError: Display + Send + Sync + 'static;
    type DecryptError: Display + Send + Sync + 'static;
    fn encrypt(
        &self,
        plaintext: &[u8],
        additional_data: &[u8],
    ) -> Pin<Box<dyn Future<Output = Result<Vec<u8>, Self::EncryptError>> + Send + '_>>;

    fn decrypt(
        &self,
        ciphertext: &[u8],
        additional_data: &[u8],
    ) -> Pin<Box<dyn Future<Output = Result<Vec<u8>, Self::DecryptError>> + Send + '_>>;

    fn encrypt_sync(
        &self,
        plaintext: &[u8],
        additional_data: &[u8],
    ) -> Result<Vec<u8>, Self::EncryptError>;

    fn decrypt_sync(
        &self,
        ciphertext: &[u8],
        additional_data: &[u8],
    ) -> Result<Vec<u8>, Self::DecryptError>;
}

impl<T> Kms for &T
where
    T: Kms,
{
    type EncryptError = T::EncryptError;

    type DecryptError = T::DecryptError;

    fn encrypt(
        &self,
        plaintext: &[u8],
        additional_data: &[u8],
    ) -> Pin<Box<dyn Future<Output = Result<Vec<u8>, Self::EncryptError>> + Send + '_>> {
        (*self).encrypt(plaintext, additional_data)
    }

    fn decrypt(
        &self,
        ciphertext: &[u8],
        additional_data: &[u8],
    ) -> Pin<Box<dyn Future<Output = Result<Vec<u8>, Self::DecryptError>> + Send + '_>> {
        (*self).decrypt(ciphertext, additional_data)
    }

    fn encrypt_sync(
        &self,
        plaintext: &[u8],
        additional_data: &[u8],
    ) -> Result<Vec<u8>, Self::EncryptError> {
        (*self).encrypt_sync(plaintext, additional_data)
    }

    fn decrypt_sync(
        &self,
        ciphertext: &[u8],
        additional_data: &[u8],
    ) -> Result<Vec<u8>, Self::DecryptError> {
        (*self).decrypt_sync(ciphertext, additional_data)
    }
}

/// `InMemory` is an in-memory [`Kms`] implementation that is not meant to be used outside of testing.
/// Ciphers are only maintained in memory so any keyrings sealed with it will be lost. Nonces are
/// static and repeated to simplify implementation.
///
/// ## Do not use outside of testing
#[derive(Debug, Clone)]
pub struct InMemory {
    key: [u8; 32],
    nonce: [u8; 12],
}
impl InMemory {
    pub fn new() -> Self {
        let key = ChaCha20Poly1305::generate_key(crate::Random);
        let nonce = ChaCha20Poly1305::generate_nonce(crate::Random);
        Self {
            key: key.into(),
            nonce: nonce.into(),
        }
    }
}

impl Default for InMemory {
    fn default() -> Self {
        Self::new()
    }
}

impl Kms for InMemory {
    type EncryptError = chacha20poly1305::Error;
    type DecryptError = chacha20poly1305::Error;

    fn encrypt(
        &self,
        plaintext: &[u8],
        additional_data: &[u8],
    ) -> Pin<Box<dyn Future<Output = Result<Vec<u8>, Self::EncryptError>> + Send + '_>> {
        let plaintext = plaintext.to_vec();
        let nonce = self.nonce;
        let nonce = chacha20poly1305::Nonce::from_slice(&nonce).to_owned();
        let cipher = ChaCha20Poly1305::new(&self.key.into());
        let aad = additional_data.to_vec();
        Box::pin(async move {
            let ciphertext = cipher.encrypt(
                &nonce,
                Payload {
                    aad: &aad,
                    msg: &plaintext,
                },
            )?;
            Ok(ciphertext)
        })
    }

    fn decrypt(
        &self,
        ciphertext: &[u8],
        additional_data: &[u8],
    ) -> Pin<Box<dyn Future<Output = Result<Vec<u8>, Self::DecryptError>> + Send + '_>> {
        let ciphertext = ciphertext.to_vec();
        let nonce = self.nonce;
        let nonce = chacha20poly1305::Nonce::from_slice(&nonce).to_owned();
        let cipher = ChaCha20Poly1305::new(&self.key.into());
        let aad = additional_data.to_vec();
        Box::pin(async move {
            let plaintext = cipher.decrypt(
                &nonce,
                Payload {
                    aad: &aad,
                    msg: &ciphertext,
                },
            )?;
            Ok(plaintext)
        })
    }

    fn encrypt_sync(
        &self,
        plaintext: &[u8],
        additional_data: &[u8],
    ) -> Result<Vec<u8>, Self::EncryptError> {
        let plaintext = plaintext.to_vec();
        let nonce = self.nonce;
        let nonce = chacha20poly1305::Nonce::from_slice(&nonce).to_owned();
        let cipher = ChaCha20Poly1305::new(&self.key.into());
        let aad = additional_data.to_vec();
        let ciphertext = cipher.encrypt(
            &nonce,
            Payload {
                aad: &aad,
                msg: &plaintext,
            },
        )?;
        Ok(ciphertext)
    }

    fn decrypt_sync(
        &self,
        ciphertext: &[u8],
        additional_data: &[u8],
    ) -> Result<Vec<u8>, Self::DecryptError> {
        let ciphertext = ciphertext.to_vec();
        let nonce = self.nonce;
        let nonce = chacha20poly1305::Nonce::from_slice(&nonce).to_owned();
        let cipher = ChaCha20Poly1305::new(&self.key.into());
        let aad = additional_data.to_vec();
        let plaintext = cipher.decrypt(
            &nonce,
            Payload {
                aad: &aad,
                msg: &ciphertext,
            },
        )?;
        Ok(plaintext)
    }
}
