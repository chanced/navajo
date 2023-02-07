mod algorithm;
mod context;
mod hasher;
mod key;
mod sink;
mod tag;

use alloc::{sync::Arc, vec};

pub use algorithm::Algorithm;
use alloc::vec::Vec;
pub use tag::Tag;

use context::*;
use key::*;
use tag::*;

use crate::{error::InvalidKeyLength, KeyStatus};

pub struct Mac {
    keys: Vec<Arc<Key>>,
    primary_key: Arc<Key>,
    primary_key_id: u32,
}

impl Mac {
    /// Create a new MAC keyring by generating a key for the given [`Algorithm`]
    /// as the primary.
    pub fn new(algorithm: Algorithm) -> Result<Self, InvalidKeyLength> {
        let bytes = algorithm.generate_key();
        let id = crate::id::gen_id();
        let inner = MacKey::new(algorithm, &bytes)?;
        let key = Arc::new(Key {
            id,
            prefix: None,
            algorithm,
            inner,
            status: KeyStatus::Primary,
        });
        Ok(Self {
            keys: vec![key.clone()],
            primary_key: key,
            primary_key_id: id,
        })
    }

    /// Create a new MAC keyring by initializing it with the given key data as
    /// primary.
    ///
    /// If the key has a prefix, such as Tink's 5 bytes, it should be trimmed
    /// from `key` and passed as `prefix`.
    pub fn new_with_external_key(
        key: &[u8],
        algorithm: Algorithm,
        prefix: Option<&[u8]>,
    ) -> Result<Self, InvalidKeyLength> {
        let id = crate::id::gen_id();
        let inner = MacKey::new(algorithm, key)?;
        let prefix = prefix.map(|p| p.to_vec());
        let key = Arc::new(Key {
            id,
            prefix,
            algorithm,
            inner,
            status: KeyStatus::Primary,
        });
        Ok(Self {
            keys: vec![key.clone()],
            primary_key: key,
            primary_key_id: id,
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
    fn create_key(
        &mut self,
        algorithm: Algorithm,
        bytes: &[u8],
        prefix: Option<&[u8]>,
    ) -> Result<(), InvalidKeyLength> {
        let mut ids = hashbrown::HashSet::with_capacity(self.keys.len());
        for key in &self.keys {
            ids.insert(key.id);
        }
        let inner = MacKey::new(algorithm, bytes)?;
        let id = crate::id::gen_unique_id(&ids);
        self.keys.push(Arc::new(Key {
            id,
            prefix: prefix.map(|p| p.to_vec()),
            algorithm,
            inner,
            status: KeyStatus::Secondary,
        }));
        Ok(())
    }
    pub fn primary_key_id(&self) -> u32 {
        self.primary_key_id
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
