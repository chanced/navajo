use alloc::{
    string::{String, ToString},
    sync::Arc,
    vec::Vec,
};

use crate::{
    error::{
        DisableKeyError, DuplicatePubIdError, KeyNotFoundError, MalformedError, OpenError,
        RemoveKeyError, SealError,
    },
    jose::{Claims, VerifiedJws},
    key::Key,
    keyring::Keyring,
    Aad, Envelope, KeyInfo, Metadata, Origin, Primitive, Rng, Status, SystemRng, Verifier,
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
    /// Opens a [`Signer`] keyring from the given `data` and validates the
    /// authenticity with `aad` by means of the [`Envelope`] `envelope`.
    ///
    /// # Errors
    /// Errors if the keyring could not be opened by the or the authenticity
    /// could not be verified by the [`Envelope`] using futures.
    ///
    /// # Example
    /// ```rust
    /// use navajo::Aad;
    /// use navajo::dsa::{ Signer, Algorithm };
    /// use navajo::envelope::InMemory;
    ///
    /// #[tokio::main]
    /// async fn main() {
    ///     let signer = Signer::new(Algorithm::Ed25519, None /* Option<String> */, None /* Option<navajo::Metadata> */);
    ///     let primary_key = signer.primary_key();
    ///     // in a real application, you would use a real key management service.
    ///     // InMemory is only suitable for testing.
    ///     let in_mem = InMemory::default();
    ///     let data = Signer::seal(Aad::empty(), &signer, &in_mem).await.unwrap();
    ///     let signer = Signer::open(Aad::empty(), data, &in_mem).await.unwrap();
    ///     assert_eq!(signer.primary_key(), primary_key);
    /// }
    /// ```
    pub async fn open<A, D, E>(aad: Aad<A>, data: D, envelope: &E) -> Result<Self, OpenError>
    where
        E: 'static + Envelope,
        D: 'static + AsRef<[u8]> + Send + Sync,
        A: 'static + AsRef<[u8]> + Send + Sync,
    {
        let primitive = Primitive::open(aad, data, envelope).await?;
        primitive
            .signer()
            .ok_or(OpenError("primitive is not Signer".into()))
    }

    /// Opens a [`Signer`] keyring from the given `data` and validates the
    /// authenticity with `aad` by means of the [`Envelope`] using
    /// blocking APIs.
    ///
    /// # Errors
    /// Errors if the keyring could not be opened by the or the authenticity
    /// could not be verified by the [`Envelope`].
    ///
    /// # Example
    /// ```rust
    /// use navajo::Aad;
    /// use navajo::dsa::{ Signer, Algorithm };
    /// use navajo::envelope::InMemory;
    ///
    /// let signer = Signer::new(Algorithm::Ed25519, None /* Option<String> */, None /* Option<navajo::Metadata> */);
    /// let primary_key = signer.primary_key();
    /// // in a real application, you would use a real key management service.
    /// // InMemory is only suitable for testing.
    /// let in_mem = InMemory::default();
    /// let data = Signer::seal_sync(Aad(&b"associated data"), &signer, &in_mem).unwrap();
    /// let signer = Signer::open_sync(Aad(&b"associated data"), &data, &in_mem).unwrap();
    /// assert_eq!(signer.primary_key(), primary_key);
    /// ```
    pub fn open_sync<A, E, C>(aad: Aad<A>, ciphertext: C, envelope: &E) -> Result<Self, OpenError>
    where
        A: AsRef<[u8]>,
        C: AsRef<[u8]>,
        E: 'static + crate::envelope::sync::Envelope,
    {
        let primitive = Primitive::open_sync(aad, ciphertext, envelope)?;
        if let Some(signer) = primitive.signer() {
            Ok(signer)
        } else {
            Err(OpenError("primitive is not a signer".into()))
        }
    }
    /// Seals an [`Signer`] keyring and tags it with `aad` for future
    /// authenticationby means of the [`Envelope`].
    ///
    /// # Errors
    /// Errors if the keyring could not be sealed by the [`Envelope`].
    ///
    /// # Example
    /// ```rust
    /// use navajo::Aad;
    /// use navajo::dsa::{ Signer, Algorithm };
    /// use navajo::envelope::InMemory;
    ///
    /// #[tokio::main]
    /// async fn main() {
    ///     let signer = Signer::new(Algorithm::Ed25519, None /* Option<String> */, None /* Option<navajo::Metadata> */);
    ///     let primary_key = signer.primary_key();
    ///     // in a real application, you would use a real key management service.
    ///     // InMemory is only suitable for testing.
    ///     let in_mem = InMemory::default();
    ///     let data = Signer::seal(Aad::empty(), &signer, &in_mem).await.unwrap();
    ///     let signer = Signer::open(Aad::empty(), data, &in_mem).await.unwrap();
    ///     assert_eq!(signer.primary_key(), primary_key);
    /// }
    /// ```
    pub async fn seal<A, E>(aad: Aad<A>, signer: &Self, envelope: &E) -> Result<Vec<u8>, SealError>
    where
        A: 'static + AsRef<[u8]> + Send + Sync,
        E: Envelope + 'static,
    {
        Primitive::Dsa(signer.clone()).seal(aad, envelope).await
    }
    /// Seals a [`Signer`] keyring and tags it with `aad` for future
    /// authenticationby means of the [`Envelope`].
    ///
    /// # Errors
    /// Errors if the keyring could not be sealed by the [`Envelope`].
    ///
    /// # Example
    /// ```rust
    /// use navajo::Aad;
    /// use navajo::dsa::{ Signer, Algorithm };
    /// use navajo::envelope::InMemory;
    ///
    /// let signer = Signer::new(Algorithm::Ed25519, None /* Option<String> */, None /* Option<navajo::Metadata> */);
    /// let primary_key = signer.primary_key();
    /// // in a real application, you would use a real key management service.
    /// // InMemory is only suitable for testing.
    /// let in_mem = InMemory::default();
    /// let ciphertext = Signer::seal_sync(Aad::empty(), &signer, &in_mem).unwrap();
    /// let signer = Signer::open_sync(Aad::empty(), ciphertext, &in_mem).unwrap();
    /// assert_eq!(signer.primary_key(), primary_key);
    /// ```
    pub fn seal_sync<A, E>(aad: Aad<A>, signer: &Self, envelope: &E) -> Result<Vec<u8>, SealError>
    where
        A: AsRef<[u8]>,
        E: 'static + crate::envelope::sync::Envelope,
    {
        Primitive::Dsa(signer.clone()).seal_sync(aad, envelope)
    }

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
