use crate::keyring::Keyring;

use super::Material;

#[derive(Clone)]
pub struct DerivedAead {
    salt: crate::hkdf::Salt,
    keyring: Keyring<Material>,
}
