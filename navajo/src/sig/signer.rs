use alloc::{string::String, sync::Arc};
use serde::Serialize;

use crate::{
    error::{DisableKeyError, DuplicatePubIdError, KeyNotFoundError, RemoveKeyError},
    key::Key,
    keyring::Keyring,
    KeyInfo, Origin, Rng, Status, SystemRng, Verifier,
};

#[cfg(not(feature = "std"))]
type Set<V> = alloc::collections::BTreeSet<V>;

use super::{Algorithm, Material, Signature, SignatureKeyInfo, SigningKey};

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
        metadata: Option<serde_json::Value>,
    ) -> Self
    where
        G: Rng,
    {
        let id = rng.u32().unwrap();
        let metadata = metadata.map(Arc::new);
        let key = SigningKey::generate(
            rng,
            algorithm,
            pub_id.unwrap_or(id.to_string()),
            metadata.clone(),
        );
        let key = Key::new(0, Status::Primary, crate::Origin::Navajo, key, metadata);
        let keyring = Keyring::new(key);
        let verifier = Verifier::from_keyring(keyring.clone());
        Self { keyring, verifier }
    }
    pub(crate) fn keyring(&self) -> &Keyring<Material> {
        &self.keyring
    }

    pub fn keys(&self) -> Vec<KeyInfo<crate::sig::Algorithm>> {
        todo!()
    }

    pub fn add_key(
        &mut self,
        algorithm: Algorithm,
        pub_id: Option<String>,
        metadata: Option<serde_json::Value>,
    ) -> Result<SignatureKeyInfo, DuplicatePubIdError> {
        let id = self.keyring.next_id(&SystemRng);
        let pub_id = pub_id.unwrap_or(id.to_string());
        let metadata = metadata.map(Arc::new);
        let signing_key = SigningKey::generate(&SystemRng, algorithm, pub_id, metadata.clone());
        let verifying_key = signing_key.verifying_key.clone();
        let key = Key::new(id, Status::Secondary, Origin::Navajo, signing_key, metadata);
        self.verifier.add_key(verifying_key)?;
        Ok(SignatureKeyInfo::new(&key))
    }

    pub fn sign(&self, message: &[u8]) -> Signature {
        self.keyring.primary().sign(message)
    }

    pub fn sign_jws(&self, payload: &impl Serialize) -> Result<String, serde_json::Error> {
        self.keyring.primary().sign_jws(payload)
    }

    pub fn verifier(&self) -> Verifier {
        self.verifier.clone()
    }

    pub fn promote_key(&mut self, key_id: u32) -> Result<SignatureKeyInfo, KeyNotFoundError> {
        let key = self.keyring.promote(key_id)?;
        Ok(SignatureKeyInfo::new(key))
    }

    pub fn enable_key(&self, key_id: u32) -> Result<KeyInfo<Algorithm>, KeyNotFoundError> {
        todo!()
    }

    pub fn disable_key(
        &mut self,
        key_id: u32,
    ) -> Result<KeyInfo<Algorithm>, DisableKeyError<Algorithm>> {
        self.keyring.disable(key_id).map(|k| k.info())
    }

    pub fn remove(
        &mut self,
        key_id: impl Into<u32>,
    ) -> Result<KeyInfo<Algorithm>, RemoveKeyError<Algorithm>> {
        let key_id = key_id.into();
        let key = self.keyring.get(key_id)?;
        self.verifier.remove(key.pub_id())?;
        self.keyring.remove(key_id).map(|k| k.info())
    }
}
