use alloc::{
    string::{String, ToString},
    sync::Arc,
    vec::Vec,
};

use crate::{
    error::{
        DisableKeyError, DuplicatePubIdError, KeyNotFoundError, MalformedError, RemoveKeyError,
    },
    jose::{Claims, VerifiedJws},
    key::Key,
    keyring::Keyring,
    KeyInfo, Metadata, Origin, Rng, Status, SystemRng, Verifier,
};

#[cfg(not(feature = "std"))]
type Set<V> = alloc::collections::BTreeSet<V>;

use super::{Algorithm, DsaKeyInfo, Material, Signature, SigningKey};

#[derive(Clone, Debug)]
pub struct Signer {
    keyring: Keyring<SigningKey>,
    verifier: Verifier,
}

impl Signer {
    pub fn new(algorithm: Algorithm, pub_id: Option<String>, meta: Option<Metadata>) -> Self {
        Self::generate(&SystemRng, algorithm, pub_id, meta)
    }

    pub(crate) fn from_keyring(keyring: Keyring<SigningKey>) -> Self {
        let verifier = Verifier::from_keyring(keyring.clone());
        Self { keyring, verifier }
    }

    fn generate<N>(
        rng: &N,
        algorithm: Algorithm,
        pub_id: Option<String>,
        metadata: Option<Metadata>,
    ) -> Self
    where
        N: Rng,
    {
        let id = rng.u32().unwrap();
        let metadata = metadata.map(Arc::new);
        let key = SigningKey::generate(
            rng,
            algorithm,
            pub_id.unwrap_or(id.to_string()),
            metadata.clone(),
        );
        let key = Key::new(id, Status::Primary, crate::Origin::Navajo, key, metadata);
        let keyring = Keyring::new(key);
        let verifier = Verifier::from_keyring(keyring.clone());
        Self { keyring, verifier }
    }
    pub(crate) fn keyring(&self) -> &Keyring<Material> {
        &self.keyring
    }

    pub fn keys(&self) -> Vec<DsaKeyInfo> {
        self.keyring.keys().iter().map(DsaKeyInfo::new).collect()
    }

    pub fn add(
        &mut self,
        algorithm: Algorithm,
        pub_id: Option<String>,
        metadata: Option<Metadata>,
    ) -> Result<DsaKeyInfo, DuplicatePubIdError> {
        let id = self.keyring.next_id(&SystemRng);
        let pub_id = pub_id.unwrap_or(id.to_string());
        let metadata = metadata.map(Arc::new);
        let signing_key = SigningKey::generate(&SystemRng, algorithm, pub_id, metadata.clone());
        let verifying_key = signing_key.verifying_key.clone();
        let key = Key::new(id, Status::Secondary, Origin::Navajo, signing_key, metadata);
        self.keyring.add(key.clone());
        self.verifier.add(verifying_key)?;
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

    pub fn sign_jws<'t>(&self, claims: Claims) -> Result<VerifiedJws<'t>, MalformedError> {
        self.keyring.primary().sign_jws(claims)
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

    pub fn delete(
        &mut self,
        key_id: impl Into<u32>,
    ) -> Result<KeyInfo<Algorithm>, RemoveKeyError<Algorithm>> {
        let key_id = key_id.into();
        let key = self.keyring.get(key_id)?;
        self.verifier.delete(key.pub_id())?;
        self.keyring.remove(key_id).map(|k| k.info())
    }

    pub fn set_key_metadata(
        &mut self,
        key_id: u32,
        metadata: Option<Metadata>,
    ) -> Result<DsaKeyInfo, KeyNotFoundError> {
        self.keyring.update_key_metadata(key_id, metadata)?;
        let key = self.keyring.get(key_id)?;
        Ok(DsaKeyInfo::new(key))
    }
}
