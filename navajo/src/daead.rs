#![doc = include_str!("./daead/README.md")]

mod algorithm;
mod material;

pub use algorithm::Algorithm;
use alloc::sync::Arc;
pub(crate) use material::Material;

use zeroize::ZeroizeOnDrop;

use crate::{
    error::{DisableKeyError, KeyNotFoundError, RemoveKeyError},
    key::Key,
    keyring::Keyring,
    KeyInfo, Metadata, Origin, Rng, Status, SystemRng,
};

#[derive(Clone, Debug, ZeroizeOnDrop)]
pub struct Daead {
    keyring: Keyring<Material>,
}

impl Daead {
    pub fn new(algorithm: Algorithm, metadata: Option<Metadata>) -> Self {
        Self::create(&SystemRng, algorithm, metadata)
    }

    fn create<G>(rng: &G, algorithm: Algorithm, metadata: Option<Metadata>) -> Self
    where
        G: Rng,
    {
        let id = rng.u32().unwrap();
        let material = Material::generate(rng, algorithm);
        let metadata = metadata.map(Arc::new);
        let key = Key::new(id, Status::Primary, Origin::Navajo, material, metadata);
        let keyring = Keyring::new(key);
        Self { keyring }
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
        let material = Material::generate(&SystemRng, algorithm);
        let id = self.keyring.next_id(&SystemRng);
        let metadata = metadata.map(Arc::new);
        let key = Key::new(id, Status::Primary, Origin::Navajo, material, metadata);
        self.keyring.add(key);
        self.keyring.last().into()
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

    pub fn disable(
        &mut self,
        key_id: u32,
    ) -> Result<KeyInfo<Algorithm>, DisableKeyError<Algorithm>> {
        self.keyring.disable(key_id).map(|key| key.info())
    }

    pub fn remove_key(
        &mut self,
        key_id: impl Into<u32>,
    ) -> Result<KeyInfo<Algorithm>, RemoveKeyError<Algorithm>> {
        self.keyring.remove(key_id).map(|k| k.info())
    }
}
