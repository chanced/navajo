use alloc::string::String;

use crate::{
    error::{DisableKeyError, KeyNotFoundError, RemoveKeyError},
    key::Key,
    keyring::Keyring,
    KeyInfo, Rng, Status, SystemRng, Verifier,
};

use super::{Algorithm, Material, Signature, SigningKey};

#[derive(Clone, Debug)]
pub struct Signer {
    keyring: Keyring<SigningKey>,
    verifier: Verifier,
}
impl Signer {
    pub fn new(
        algorithm: Algorithm,
        pub_id: Option<String>,
        meta: Option<serde_json::Value>,
    ) -> Self {
        Self::generate(&SystemRng, algorithm, pub_id, meta)
    }
    fn generate<G>(
        rng: &G,
        algorithm: Algorithm,
        pub_id: Option<String>,
        meta: Option<serde_json::Value>,
    ) -> Self
    where
        G: Rng,
    {
        let id = rng.u32().unwrap();
        let key = SigningKey::generate(rng, algorithm, pub_id.unwrap_or(id.to_string()));
        let key = Key::new(0, Status::Primary, crate::Origin::Navajo, key, meta);
        let keyring = Keyring::new(key);
        let verifier = Verifier::from_keyring(keyring.clone());
        Self { keyring, verifier }
    }
    pub(crate) fn keyring(&self) -> &Keyring<Material> {
        &self.keyring
    }

    pub fn keys(&self) -> Vec<KeyInfo<crate::signature::Algorithm>> {
        todo!()
    }

    pub fn add_key(
        &mut self,
        algorithm: Algorithm,
        pub_id: Option<String>,
        metadata: Option<serde_json::Value>,
    ) -> KeyInfo<Algorithm> {
        todo!()
    }

    pub fn sign(&self, message: &[u8]) -> Signature {
        self.keyring.primary().sign(message)
    }
    pub fn verifier(&self) -> Verifier {
        self.verifier.clone()
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
