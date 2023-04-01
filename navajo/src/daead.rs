#![doc = include_str!("./daead/README.md")]

mod algorithm;
mod material;

pub use algorithm::Algorithm;
use alloc::sync::Arc;
pub(crate) use material::Material;

use zeroize::ZeroizeOnDrop;

use crate::{
    error::{DisableKeyError, KeyNotFoundError, RemoveKeyError},
    keyring::{gen_id, Keyring},
    KeyInfo, Metadata, Rng, SystemRng,
};

#[derive(Clone, Debug, ZeroizeOnDrop)]
pub struct Daead {
    keyring: Keyring<Material>,
}

impl Daead {
    pub fn new(algorithm: Algorithm, metadata: Option<Metadata>) -> Self {
        Self::generate(&SystemRng, algorithm, metadata)
    }

    fn generate<G>(rng: &G, algorithm: Algorithm, metadata: Option<Metadata>) -> Self
    where
        G: Rng,
    {
        // let id = gen_id(rng);
        // let metadata = metadata.map(Arc::new);
        // let key = Material::generate(rng, algorithm, metadata.clone());
        // let key = Key::new(0, Status::Primary, crate::Origin::Navajo, key, metadata);
        // let keyring = Keyring::new(key);
        todo!()
        // Self { keyring }
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
        metadata: Option<Metadata>,
    ) -> KeyInfo<Algorithm> {
        // self.keyring.add(&SystemRng, material, origin, meta)
        todo!()
    }

    pub fn promote(
        &mut self,
        key_id: impl Into<u32>,
    ) -> Result<KeyInfo<Algorithm>, KeyNotFoundError> {
        self.keyring.promote(key_id).map(|key| key.info())
    }

    pub fn enable(
        &mut self,
        key_id: impl Into<u32>,
    ) -> Result<KeyInfo<Algorithm>, KeyNotFoundError> {
        self.keyring.enable(key_id).map(|key| key.info())
    }

    pub fn disable(&self, key_id: u32) -> Result<KeyInfo<Algorithm>, DisableKeyError<Algorithm>> {
        todo!()
    }

    pub fn remove_key(
        &mut self,
        key_id: impl Into<u32>,
    ) -> Result<KeyInfo<Algorithm>, RemoveKeyError<Algorithm>> {
        self.keyring.remove(key_id).map(|k| k.info())
    }
}
