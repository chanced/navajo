use core::{any::Any, pin::Pin};

use aes_gcm::{aead::Aead as RustCryptoAead, AeadCore};
#[cfg(not(feature = "std"))]
use alloc::{borrow::ToOwned, boxed::Box, vec, vec::Vec};
use chacha20poly1305::{aead::Payload, ChaCha20Poly1305, KeyInit};

use futures::Future;

use crate::{envelope, error::Error, Aad};
#[allow(clippy::type_complexity)]
pub trait Envelope {
    type EncryptError: core::fmt::Display + core::fmt::Debug + Send + Sync;
    type DecryptError: core::fmt::Display + core::fmt::Debug + Send + Sync;
    fn encrypt_dek<A, P>(
        &self,
        aad: Aad<A>,
        plaintext: P,
    ) -> Pin<Box<dyn Future<Output = Result<Vec<u8>, Self::EncryptError>> + Send + '_>>
    where
        A: 'static + AsRef<[u8]> + Send + Sync,
        P: 'static + AsRef<[u8]> + Send + Sync;

    fn decrypt_dek<A, C>(
        &self,
        aad: Aad<A>,
        ciphertext: C,
    ) -> Pin<Box<dyn Future<Output = Result<Vec<u8>, Self::DecryptError>> + Send + '_>>
    where
        A: 'static + AsRef<[u8]> + Send + Sync,
        C: 'static + AsRef<[u8]> + Send + Sync;
}

pub mod sync {
    use alloc::vec::Vec;

    pub trait Envelope {
        type EncryptError: core::fmt::Display + core::fmt::Debug + Send + Sync;
        type DecryptError: core::fmt::Display + core::fmt::Debug + Send + Sync;

        fn encrypt_dek<A, P>(
            &self,
            aad: super::Aad<A>,
            plaintext: P,
        ) -> Result<Vec<u8>, Self::EncryptError>
        where
            A: AsRef<[u8]>,
            P: AsRef<[u8]>;

        fn decrypt_dek<A, C>(
            &self,
            aad: super::Aad<A>,
            ciphertext: C,
        ) -> Result<Vec<u8>, Self::DecryptError>
        where
            A: AsRef<[u8]>,
            C: AsRef<[u8]>;
    }
}

/// `InMemory` is an in-memory [`Envelope`] implementation that is not meant to be used outside of testing.
/// Ciphers are only maintained in memory so any keyrings sealed with it will be lost. Nonces are
/// static and repeated to simplify implementation.
///
/// **Do not use outside of testing**
#[derive(Debug, Clone)]
pub struct InMemory {
    key: [u8; 32],
    nonce: [u8; 12],
}
impl InMemory {
    pub fn new() -> Self {
        let key = ChaCha20Poly1305::generate_key(crate::SystemRng);
        let nonce = ChaCha20Poly1305::generate_nonce(crate::SystemRng);
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

    fn encrypt_dek<A, P>(
        &self,
        aad: Aad<A>,
        plaintext: P,
    ) -> Pin<Box<dyn Future<Output = Result<Vec<u8>, Self::EncryptError>> + Send + '_>>
    where
        A: 'static + AsRef<[u8]> + Send + Sync,
        P: 'static + AsRef<[u8]> + Send + Sync,
    {
        Box::pin(async move { envelope::sync::Envelope::encrypt_dek(self, aad, plaintext) })
    }

    fn decrypt_dek<A, C>(
        &self,
        aad: Aad<A>,
        ciphertext: C,
    ) -> Pin<Box<dyn Future<Output = Result<Vec<u8>, Self::DecryptError>> + Send + '_>>
    where
        A: 'static + AsRef<[u8]> + Send + Sync,
        C: 'static + AsRef<[u8]> + Send + Sync,
    {
        Box::pin(async move { envelope::sync::Envelope::decrypt_dek(self, aad, ciphertext) })
    }
}
impl envelope::sync::Envelope for InMemory {
    type EncryptError = chacha20poly1305::Error;
    type DecryptError = chacha20poly1305::Error;
    fn encrypt_dek<A, P>(&self, aad: Aad<A>, plaintext: P) -> Result<Vec<u8>, Self::EncryptError>
    where
        A: AsRef<[u8]>,
        P: AsRef<[u8]>,
    {
        let nonce = self.nonce;
        let nonce = chacha20poly1305::Nonce::from_slice(&nonce).to_owned();
        let cipher = ChaCha20Poly1305::new(&self.key.into());
        let ciphertext = cipher.encrypt(
            &nonce,
            Payload {
                aad: aad.as_ref(),
                msg: plaintext.as_ref(),
            },
        )?;
        Ok(ciphertext)
    }

    fn decrypt_dek<A, C>(&self, aad: Aad<A>, ciphertext: C) -> Result<Vec<u8>, Self::DecryptError>
    where
        A: AsRef<[u8]>,
        C: AsRef<[u8]>,
    {
        let nonce = self.nonce;
        let nonce = chacha20poly1305::Nonce::from_slice(&nonce).to_owned();
        let cipher = ChaCha20Poly1305::new(&self.key.into());
        let plaintext = cipher.decrypt(
            &nonce,
            Payload {
                aad: aad.as_ref(),
                msg: ciphertext.as_ref(),
            },
        )?;
        Ok(plaintext)
    }
}

/// `PlaintextJson` implements [`Envelope`] but does not encrypt or decrypt the
/// Data Encryption Key (DEK). Keyrings have special handling for the usage of
/// `PlaintextJson`as an [`Envelope`]. The output of `seal` is raw, unencrypted
/// JSON while `unseal` will deserialize json.
///
#[derive(Debug, Clone)]
pub struct PlaintextJson;

impl Envelope for PlaintextJson {
    type EncryptError = serde_json::Error;
    type DecryptError = serde_json::Error;

    fn encrypt_dek<A, P>(
        &self,
        _aad: Aad<A>,
        _plaintext: P,
    ) -> Pin<Box<dyn Future<Output = Result<Vec<u8>, Self::EncryptError>> + Send + '_>>
    where
        A: 'static + AsRef<[u8]>,
        P: 'static + AsRef<[u8]>,
    {
        Box::pin(async move { Ok(vec![]) })
    }

    fn decrypt_dek<A, C>(
        &self,
        _aad: Aad<A>,
        _plaintext: C,
    ) -> Pin<Box<dyn Future<Output = Result<Vec<u8>, Self::DecryptError>> + Send + '_>>
    where
        A: 'static + AsRef<[u8]>,
        C: 'static + AsRef<[u8]>,
    {
        Box::pin(async move { Ok(vec![]) })
    }
}

impl envelope::sync::Envelope for PlaintextJson {
    type EncryptError = serde_json::Error;
    type DecryptError = serde_json::Error;
    fn encrypt_dek<A, P>(&self, _aad: Aad<A>, _plaintext: P) -> Result<Vec<u8>, Self::EncryptError>
    where
        A: AsRef<[u8]>,
        P: AsRef<[u8]>,
    {
        Ok(vec![])
    }

    fn decrypt_dek<A, C>(&self, _aad: Aad<A>, _ciphertext: C) -> Result<Vec<u8>, Self::DecryptError>
    where
        A: AsRef<[u8]>,
        C: AsRef<[u8]>,
    {
        Ok(vec![])
    }
}
pub(crate) fn is_plaintext<T: Any>(envelope: &T) -> bool {
    let envelope = envelope as &dyn Any;
    envelope.downcast_ref::<PlaintextJson>().is_some()
}

#[cfg(test)]
mod tests {

    #[cfg(all(feature = "std", feature = "mac", feature = "hmac", feature = "sha2"))]
    #[tokio::test]
    async fn test_mac_to_json() {
        use super::*;
        use crate::mac::{Algorithm, Mac};

        let mut m = Mac::new(Algorithm::Sha256, None);

        m.add(Algorithm::Sha512, None);

        let m_keys = m.keys();

        let envelope = PlaintextJson;
        let result = Mac::seal(Aad::empty(), &m, &envelope).await.unwrap();
        let value = serde_json::from_slice::<serde_json::Value>(&result);
        assert!(value.is_ok());
        let value = value.unwrap();

        assert!(value.is_object());

        let value = value.as_object().unwrap();
        assert_eq!(value.get("kind").unwrap(), "MAC");
        let keyring = value.get("keys");
        assert!(keyring.is_some());
        let keys = keyring.unwrap();
        assert!(keys.is_array());
        let keys = keys.as_array().unwrap();

        assert_eq!(keys.len(), m_keys.len());

        for (i, k) in keys.iter().enumerate() {
            assert!(k.is_object());
            let k = k.as_object().unwrap();
            let id = k.get("id");
            assert!(id.is_some());
            let id = id.unwrap();
            assert!(id.is_number());
            let id = id.as_u64().unwrap() as u32;
            assert_eq!(id, m_keys[i].id);

            let algorithm = k.get("alg");
            assert!(algorithm.is_some());
            let algorithm = algorithm.unwrap();
            assert!(algorithm.is_string());
            let algorithm = algorithm.as_str().unwrap();
            assert_eq!(algorithm, m_keys[i].algorithm.to_string());
        }
        assert_eq!(value.get("kind").unwrap(), "MAC");

        let _v = Mac::open(Aad::empty(), result, &envelope).await.unwrap();
    }
}
