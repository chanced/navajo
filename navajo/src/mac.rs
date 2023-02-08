mod algorithm;
mod context;
mod hasher;
mod key;
mod sink;
mod stream;
mod tag;
mod verifier;

pub use algorithm::Algorithm;
pub use stream::{ComputeMacStream, MacStream, VerifyMacStream};
pub use tag::Tag;

use crate::error::InvalidKeyLength;
use crate::{KeyInfo, Keyring};
use context::*;
use hasher::Hasher;
use key::*;
use tag::*;

pub struct Mac {
    keyring: Keyring<Material>,
}

impl Mac {
    /// Create a new MAC keyring by generating a key for the given [`Algorithm`]
    /// as the primary.
    pub fn new(algorithm: Algorithm, meta: Option<serde_json::value::Value>) -> Self {
        let bytes = algorithm.generate_key();
        let inner = MacKey::new(algorithm, &bytes).unwrap(); // safe, the key is valid
        let key = Material {
            bytes,
            prefix: None,
            algorithm,
            inner,
        };
        Self {
            keyring: Keyring::new(key, meta),
        }
    }

    /// Create a new MAC keyring by initializing it with the given key data as
    /// primary.
    ///
    /// If the key has a prefix, such as Tink's 5 bytes, it should be trimmed
    /// from `key` and passed as `prefix`.
    pub fn new_with_external_key<'de>(
        key: &[u8],
        algorithm: Algorithm,
        prefix: Option<&[u8]>,
        meta: Option<serde_json::Value>,
    ) -> Result<Self, InvalidKeyLength> {
        let inner = MacKey::new(algorithm, key)?;
        let prefix = prefix.map(|p| p.to_vec());

        let key = Material {
            prefix,
            algorithm,
            inner,
            bytes: key.to_vec(),
        };

        Ok(Self {
            keyring: Keyring::new(key, meta),
        })
    }

    pub fn add_generated_key(&mut self, algorithm: Algorithm) -> Result<(), InvalidKeyLength> {
        let bytes = algorithm.generate_key();
        self.create_key(algorithm, &bytes, None)
    }
    pub fn add_external_key(
        &mut self,
        key: &[u8],
        algorithm: Algorithm,
        prefix: Option<&[u8]>,
    ) -> Result<(), InvalidKeyLength> {
        self.create_key(algorithm, key, prefix)
    }
    pub fn primary_key(&self) -> KeyInfo<Algorithm> {
        self.keyring.primary_key().info()
    }

    pub fn keys(&self) -> impl Iterator<Item = KeyInfo<Algorithm>> + '_ {
        self.keyring.keys().map(|k| k.info())
    }

    pub(super) fn keyring(&self) -> &Keyring<Material> {
        &self.keyring
    }

    fn create_key(
        &mut self,
        algorithm: Algorithm,
        bytes: &[u8],
        prefix: Option<&[u8]>,
    ) -> Result<(), InvalidKeyLength> {
        algorithm.validate_key_len(bytes.len())?;
        Ok(())
    }
}

macro_rules! rust_crypto_internals {
    ($input:tt) => {
        rust_crypto_internal_tags!($input);
        rust_crypto_contexts!($input);
        rust_crypto_keys!($input);
    };
}
rust_crypto_internals!({
    hmac: {
        ring: [Sha256, Sha384, Sha512],
        sha2: [Sha224, Sha512_224, Sha512_256],
        sha3: [Sha3_224, Sha3_256, Sha3_384, Sha3_512],
    },
    cmac: {
        aes: [Aes128, Aes192, Aes256]
    }
});
