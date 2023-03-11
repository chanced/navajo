#![doc = include_str!("./daead/README.md")]

mod algorithm;
mod material;

pub use algorithm::Algorithm;
pub(crate) use material::Material;

use zeroize::ZeroizeOnDrop;

use crate::keyring::Keyring;

#[derive(Clone, Debug, ZeroizeOnDrop)]
pub struct Daead {
    keyring: Keyring<Material>,
}

impl Daead {
    pub fn new(algorithm: Algorithm, metadata: Option<serde_json::Value>) -> Self {
        todo!()
    }
    pub(crate) fn keyring(&self) -> &Keyring<Material> {
        &self.keyring
    }
    pub(crate) fn from_keyring(keyring: Keyring<Material>) -> Self {
        Self { keyring }
    }
}
