#![doc = include_str!("./daead/README.md")]

mod algorithm;
mod material;

pub use algorithm::Algorithm;
pub(crate) use material::Material;

use zeroize::ZeroizeOnDrop;

use crate::{error::{KeyNotFoundError, DisableKeyError, RemoveKeyError}, keyring::Keyring, KeyInfo, SystemRng};

#[derive(Clone, Debug, ZeroizeOnDrop)]
pub struct Daead {
    keyring: Keyring<Material>,
}

impl Daead {
    pub fn new(_algorithm: Algorithm, _metadata: Option<serde_json::Value>) -> Self {
        todo!()
    }
    pub(crate) fn keyring(&self) -> &Keyring<Material> {
        &self.keyring
    }
    pub(crate) fn from_keyring(keyring: Keyring<Material>) -> Self {
        Self { keyring }
    }

    pub fn keys(&self) -> Vec<KeyInfo<crate::daead::Algorithm>> {
        todo!()
    }

    pub fn add_key(
        &mut self,
        algorithm: Algorithm,
        metadata: Option<serde_json::Value>,
    ) -> KeyInfo<Algorithm> {
        // self.keyring.add(&SystemRng, material, origin, meta)
        todo!()
    }

    pub fn promote_key(
        &mut self,
        key_id: impl Into<u32>,
    ) -> Result<KeyInfo<Algorithm>, KeyNotFoundError> {
        self.keyring.promote(key_id).map(|key| key.info())
    }

    pub fn enable_key(
        &mut self,
        key_id: impl Into<u32>,
    ) -> Result<KeyInfo<Algorithm>, KeyNotFoundError> {
        self.keyring.enable(key_id).map(|key| key.info())
    }

    pub fn disable_key(&self, key_id: u32) -> Result<KeyInfo<Algorithm>, DisableKeyError<Algorithm>> {
        todo!()
    }

    pub fn remove_key(
        &mut self,
        key_id: impl Into<u32>,
    ) -> Result<KeyInfo<Algorithm>, RemoveKeyError<Algorithm>> {
        self.keyring.remove(key_id).map(|k| k.info())
    }
}
