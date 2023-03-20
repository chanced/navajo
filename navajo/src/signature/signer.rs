use alloc::string::String;

use crate::{
    error::{DisableKeyError, KeyNotFoundError, RemoveKeyError},
    keyring::Keyring,
    KeyInfo,
};

use super::{Algorithm, Material, Signature, SigningKey};

#[derive(Clone, Debug)]
pub struct Signer {
    keyring: Keyring<SigningKey>,
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
        // let signing_key = crate::signature::signing_key::
        todo!()
    }

    pub fn keys(&self) -> Vec<KeyInfo<crate::signature::Algorithm>> {
        todo!()
    }

    pub fn add_key(
        &mut self,
        algorithm: Algorithm,
        metadata: Option<serde_json::Value>,
    ) -> KeyInfo<Algorithm> {
        todo!()
    }

    pub fn sign(&self, message: &[u8]) -> Signature {
        self.keyring.primary().sign(message)
    }

    pub fn promote_key(&mut self, key_id: u32) -> Result<KeyInfo<Algorithm>, KeyNotFoundError> {
        todo!()
    }

    pub fn enable_key(&self, key_id: u32) -> Result<KeyInfo<Algorithm>, KeyNotFoundError> {
        todo!()
    }

    pub fn disable_key(
        &self,
        key_id: u32,
    ) -> Result<KeyInfo<Algorithm>, DisableKeyError<Algorithm>> {
        todo!()
    }

    pub fn remove_key(
        &mut self,
        key_id: impl Into<u32>,
    ) -> Result<KeyInfo<Algorithm>, RemoveKeyError<Algorithm>> {
        self.keyring.remove(key_id).map(|k| k.info())
    }
}
