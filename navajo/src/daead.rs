#![doc = include_str!("./daead/README.md")]

mod algorithm;
mod material;

pub use algorithm::Algorithm;
pub(crate) use material::Material;

use serde_json::Value;
use zeroize::ZeroizeOnDrop;

use crate::{key::KeyMaterial, keyring::Keyring, sensitive};

#[derive(Clone, Debug, ZeroizeOnDrop)]
pub struct Daead {
    keyring: Keyring<Material>,
}

impl Daead {
    pub(crate) fn keyring(&self) -> &Keyring<Material> {
        &self.keyring
    }
    pub(crate) fn from_keyring(keyring: Keyring<Material>) -> Self {
        Self { keyring }
    }
}
