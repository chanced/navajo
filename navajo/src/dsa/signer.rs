use alloc::{string::String, sync::Arc};
use serde::{de::DeserializeOwned, Serialize};

use crate::{
    error::{
        DisableKeyError, DuplicatePubIdError, KeyNotFoundError, MalformedError, RemoveKeyError,
    },
    key::Key,
    keyring::Keyring,
    KeyInfo, Origin, Rng, Status, SystemRng, Verifier,
};

#[cfg(not(feature = "std"))]
type Set<V> = alloc::collections::BTreeSet<V>;

use super::{Algorithm, DsaKeyInfo, Material, Signature, SigningKey, Validate};

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

    pub(crate) fn from_keyring(keyring: Keyring<SigningKey>) -> Self {
        let verifier = Verifier::from_keyring(keyring.clone());
        Self { keyring, verifier }
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

    pub fn keys(&self) -> Vec<DsaKeyInfo> {
        todo!()
    }

    pub fn add_key(
        &mut self,
        algorithm: Algorithm,
        pub_id: Option<String>,
        metadata: Option<serde_json::Value>,
    ) -> Result<DsaKeyInfo, DuplicatePubIdError> {
        let id = self.keyring.next_id(&SystemRng);
        let pub_id = pub_id.unwrap_or(id.to_string());
        let metadata = metadata.map(Arc::new);
        let signing_key = SigningKey::generate(&SystemRng, algorithm, pub_id, metadata.clone());
        let verifying_key = signing_key.verifying_key.clone();
        let key = Key::new(id, Status::Secondary, Origin::Navajo, signing_key, metadata);
        self.keyring.add(key.clone());
        self.verifier.add_key(verifying_key)?;
        Ok(DsaKeyInfo::new(&key))
    }

    pub fn primary_key(&self) -> DsaKeyInfo {
        DsaKeyInfo::new(self.keyring.primary())
    }
    pub fn primary_key_id(&self) -> &str {
        self.keyring.primary().pub_id()
    }

    pub fn sign(&self, message: &[u8]) -> Signature {
        self.keyring.primary().sign(message)
    }

    pub fn sign_jws<P>(&self, payload: &P) -> Result<String, MalformedError>
    where
        P: Serialize + DeserializeOwned + Clone + core::fmt::Debug,
    {
        self.keyring.primary().sign_jws(payload)
    }

    pub fn verifier(&self) -> Verifier {
        self.verifier.clone()
    }

    pub fn promote(&mut self, key_id: u32) -> Result<DsaKeyInfo, KeyNotFoundError> {
        let key = self.keyring.promote(key_id)?;
        Ok(DsaKeyInfo::new(key))
    }

    pub fn enable(&mut self, key_id: u32) -> Result<DsaKeyInfo, KeyNotFoundError> {
        self.keyring.enable(key_id)?;
        let key = self.keyring.get(key_id)?;
        Ok(DsaKeyInfo::new(key))
    }

    pub fn disable(&mut self, key_id: u32) -> Result<DsaKeyInfo, DisableKeyError<Algorithm>> {
        self.keyring.disable(key_id)?;
        let key = self.keyring.get(key_id)?;
        Ok(DsaKeyInfo::new(key))
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
