use crate::keyring::Keyring;

use super::{Algorithm, Material};

pub struct Signer {
    keyring: Keyring<Material>,
}
impl Signer {
    pub(crate) fn keyring(&self) -> &Keyring<Material> {
        &self.keyring
    }
    pub(crate) fn from_keyring(keyring: Keyring<Material>) -> Self {
        Self { keyring }
    }

    pub fn new(
        algorithm: Algorithm,
        pub_id: Option<String>,
        meta: Option<serde_json::Value>,
    ) -> Self {
        todo!()
        // let material = Material::new(algorithm)
        // let keyring = Keyring::new();
        // Signature { keyring:  }
    }
}
