use core::{any::Any, fmt::Display, pin::Pin};

use aes_gcm::{aead::Aead as RustCryptoAead, AeadCore};
use alloc::{borrow::ToOwned, boxed::Box, vec::Vec};
use chacha20poly1305::{aead::Payload, ChaCha20Poly1305, KeyInit};

use futures::Future;
#[allow(clippy::type_complexity)]
pub trait Envelope {
    type EncryptError: Display + Send + Sync;
    type DecryptError: Display + Send + Sync;
    fn encrypt(
        &self,
        plaintext: &[u8],
        associated_data: &[u8],
    ) -> Pin<Box<dyn Future<Output = Result<Vec<u8>, Self::EncryptError>> + Send + '_>>;

    fn decrypt(
        &self,
        ciphertext: &[u8],
        associated_data: &[u8],
    ) -> Pin<Box<dyn Future<Output = Result<Vec<u8>, Self::DecryptError>> + Send + '_>>;

    fn encrypt_sync(
        &self,
        plaintext: &[u8],
        associated_data: &[u8],
    ) -> Result<Vec<u8>, Self::EncryptError>;

    fn decrypt_sync(
        &self,
        ciphertext: &[u8],
        associated_data: &[u8],
    ) -> Result<Vec<u8>, Self::DecryptError>;
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

impl Envelope for InMemory {
    type EncryptError = chacha20poly1305::Error;
    type DecryptError = chacha20poly1305::Error;

    fn encrypt(
        &self,
        plaintext: &[u8],
        associated_data: &[u8],
    ) -> Pin<Box<dyn Future<Output = Result<Vec<u8>, Self::EncryptError>> + Send + '_>> {
        let plaintext = plaintext.to_vec();
        let nonce = self.nonce;
        let nonce = chacha20poly1305::Nonce::from_slice(&nonce).to_owned();
        let cipher = ChaCha20Poly1305::new(&self.key.into());
        let aad = associated_data.to_vec();
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
        associated_data: &[u8],
    ) -> Pin<Box<dyn Future<Output = Result<Vec<u8>, Self::DecryptError>> + Send + '_>> {
        let ciphertext = ciphertext.to_vec();
        let nonce = self.nonce;
        let nonce = chacha20poly1305::Nonce::from_slice(&nonce).to_owned();
        let cipher = ChaCha20Poly1305::new(&self.key.into());
        let aad = associated_data.to_vec();
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
        associated_data: &[u8],
    ) -> Result<Vec<u8>, Self::EncryptError> {
        let plaintext = plaintext.to_vec();
        let nonce = self.nonce;
        let nonce = chacha20poly1305::Nonce::from_slice(&nonce).to_owned();
        let cipher = ChaCha20Poly1305::new(&self.key.into());
        let aad = associated_data.to_vec();
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
        associated_data: &[u8],
    ) -> Result<Vec<u8>, Self::DecryptError> {
        let ciphertext = ciphertext.to_vec();
        let nonce = self.nonce;
        let nonce = chacha20poly1305::Nonce::from_slice(&nonce).to_owned();
        let cipher = ChaCha20Poly1305::new(&self.key.into());
        let aad = associated_data.to_vec();
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

/// Cleartext implements [`Envelope`] is a noop and does not encrypt or decrypt
/// the Data Encryption Key (DEK). The keyrings have special handling for the usage
/// of Cleartext as an Envelope resulting in the `seal` and `unseal` operations being
/// serialized and deserialized, respecitively, to raw json without encryption.
///
pub struct Cleartext;

impl Envelope for Cleartext {
    type EncryptError = String;
    type DecryptError = String;

    fn encrypt(
        &self,
        _plaintext: &[u8],
        _associated_data: &[u8],
    ) -> Pin<Box<dyn Future<Output = Result<Vec<u8>, Self::EncryptError>> + Send + '_>> {
        Box::pin(async move { Ok(vec![]) })
    }

    fn decrypt(
        &self,
        _cleartext: &[u8],
        _associated_data: &[u8],
    ) -> Pin<Box<dyn Future<Output = Result<Vec<u8>, Self::DecryptError>> + Send + '_>> {
        Box::pin(async move { Ok(vec![]) })
    }

    fn encrypt_sync(
        &self,
        _plaintext: &[u8],
        _associated_data: &[u8],
    ) -> Result<Vec<u8>, Self::EncryptError> {
        Ok(vec![])
    }

    fn decrypt_sync(
        &self,
        _ciphertext: &[u8],
        _associated_data: &[u8],
    ) -> Result<Vec<u8>, Self::DecryptError> {
        Ok(vec![])
    }
}

pub(crate) fn is_cleartext<'a, T: Envelope + Any + 'a>(envelope: &T) -> bool {
    let envelope = envelope as &dyn Any;
    envelope.downcast_ref::<Cleartext>().is_some()
        || envelope.downcast_ref::<&Cleartext>().is_some()
}
