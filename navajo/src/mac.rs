mod algorithm;
mod compute;
mod context;
mod entry;
mod key_info;
mod material;
mod output;
mod stream;
mod tag;
mod try_stream;
mod verify;

pub use algorithm::Algorithm;
pub use compute::Compute;
pub use key_info::MacKeyInfo;
pub use stream::{ComputeStream, StreamMac, VerifyStream};
pub use try_stream::{ComputeTryStream, TryStreamMac, VerifyTryStream};

pub use tag::Tag;
pub use verify::Verify;

use crate::error::{InvalidKeyLength, KeyNotFoundError, RemoveKeyError};
use crate::{KeyInfo, Keyring, Origin};
use alloc::vec::Vec;
use context::*;
use material::*;
use output::Output;
use output::{rust_crypto_internal_tag, rust_crypto_internal_tags};

pub struct Mac {
    keyring: Keyring<Material>,
}

impl Mac {
    /// Create a new MAC keyring by generating a key for the given [`Algorithm`]
    /// as the primary.
    pub fn new(algorithm: Algorithm, meta: Option<serde_json::value::Value>) -> Self {
        let bytes = algorithm.generate_key();
        // safe, the key is generated
        let material = Material::new(&bytes, None, algorithm).unwrap();

        Self {
            keyring: Keyring::new(material, Origin::Generated, meta),
        }
    }

    pub fn compute(&self) -> Compute {
        Compute::new(self)
    }

    pub fn verify<T>(&self, tag: T) -> Verify<T>
    where
        T: AsRef<Tag> + Send + Sync,
    {
        Verify::new(tag, self)
    }

    /// Create a new MAC keyring by initializing it with the given key data as
    /// primary.
    pub fn new_with_external_key(
        key: &[u8],
        algorithm: Algorithm,
        prefix: Option<&[u8]>,
        meta: Option<serde_json::Value>,
    ) -> Result<Self, InvalidKeyLength> {
        // safe, the key is generated
        let material = Material::new(key, prefix, algorithm)?;
        Ok(Self {
            keyring: Keyring::new(material, Origin::Generated, meta),
        })
    }

    pub fn add_generated_key(
        &mut self,
        algorithm: Algorithm,
        meta: Option<serde_json::Value>,
    ) -> Result<MacKeyInfo, InvalidKeyLength> {
        let bytes = algorithm.generate_key();
        self.create_key(algorithm, &bytes, None, Origin::Generated, meta)
    }
    pub fn add_external_key(
        &mut self,
        key: &[u8],
        algorithm: Algorithm,
        prefix: Option<&[u8]>,
        meta: Option<serde_json::Value>,
    ) -> Result<MacKeyInfo, InvalidKeyLength> {
        self.create_key(algorithm, key, prefix, Origin::External, meta)
    }
    /// Returns [`MacKeyInfo`] for the primary key.
    pub fn primary_key(&self) -> MacKeyInfo {
        self.keyring.primary_key().into()
    }
    /// Returns a [`Vec`] containing a [`KeyInfo`](crate::key::KeyInfo) for each key in this keyring.
    pub fn keys(&self) -> Vec<MacKeyInfo> {
        self.keyring.keys().iter().map(MacKeyInfo::new).collect()
    }

    pub fn promote_key(
        &mut self,
        key_id: impl Into<u32>,
    ) -> Result<MacKeyInfo, crate::error::KeyNotFoundError> {
        self.keyring.promote(key_id).map(MacKeyInfo::new)
    }

    pub fn disable_key(
        &mut self,
        key_id: impl Into<u32>,
    ) -> Result<MacKeyInfo, crate::error::DisableKeyError<Algorithm>> {
        self.keyring.disable(key_id).map(MacKeyInfo::new)
    }

    pub fn enable_key(&mut self, key_id: impl Into<u32>) -> Result<MacKeyInfo, KeyNotFoundError> {
        self.keyring.enable(key_id).map(MacKeyInfo::new)
    }

    pub fn remove_key(
        &mut self,
        key_id: impl Into<u32>,
    ) -> Result<MacKeyInfo, RemoveKeyError<Algorithm>> {
        self.keyring.remove(key_id).map(|k| MacKeyInfo::new(&k))
    }

    pub fn update_key_meta(
        &mut self,
        key_id: impl Into<u32>,
        meta: Option<serde_json::Value>,
    ) -> Result<MacKeyInfo, KeyNotFoundError> {
        self.keyring.update_meta(key_id, meta).map(MacKeyInfo::new)
    }

    fn keyring(&self) -> &Keyring<Material> {
        &self.keyring
    }

    fn create_key(
        &mut self,
        algorithm: Algorithm,
        bytes: &[u8],
        prefix: Option<&[u8]>,
        origin: Origin,
        meta: Option<serde_json::Value>,
    ) -> Result<MacKeyInfo, InvalidKeyLength> {
        let material = Material::new(bytes, prefix, algorithm)?;
        Ok(MacKeyInfo::new(self.keyring.add(material, origin, meta)))
    }
}

impl AsRef<Mac> for Mac {
    fn as_ref(&self) -> &Self {
        self
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
