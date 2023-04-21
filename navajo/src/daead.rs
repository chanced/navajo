#![doc = include_str!("./daead/README.md")]

mod algorithm;
mod cipher;
mod key_info;
mod material;
use crate::{
    error::{
        DisableKeyError, EncryptDeterministicallyError, KeyNotFoundError, OpenError,
        RemoveKeyError, SealError,
    },
    key::Key,
    keyring::Keyring,
    Aad, Buffer, Envelope, Metadata, Origin, Primitive, Rng, Status, SystemRng,
};
use alloc::vec::Vec;
use zeroize::ZeroizeOnDrop;

pub(crate) use material::Material;

pub use algorithm::Algorithm;
pub use key_info::{KeyInfo, KeyringInfo};

#[derive(Clone, Debug, ZeroizeOnDrop)]
pub struct Daead {
    keyring: Keyring<Material>,
}

impl Daead {
    /// Opens a [`Daead`] keyring from the given `data` and validates the
    /// authenticity with `aad` by means of the [`Envelope`] `envelope`.
    ///
    /// # Errors
    /// Errors if the keyring could not be opened by the or the authenticity
    /// could not be verified by the [`Envelope`] using futures.
    ///
    /// # Example
    /// ```rust
    /// use navajo::Aad;
    /// use navajo::daead::{ Daead, Algorithm };
    /// use navajo::envelope::InMemory;
    ///
    /// #[tokio::main]
    /// async fn main() {
    ///     let daead = Daead::new(Algorithm::Aes256Siv, None);
    ///     let primary_key = daead.primary_key();
    ///     // in a real application, you would use a real key management service.
    ///     // InMemory is only suitable for testing.
    ///     let in_mem = InMemory::default();
    ///     let data = Daead::seal(Aad::empty(), &daead, &in_mem).await.unwrap();
    ///     let daead = Daead::open(Aad::empty(), data, &in_mem).await.unwrap();
    ///     assert_eq!(daead.primary_key(), primary_key);
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
            .daead()
            .ok_or(OpenError("primitive is not Daead".into()))
    }

    /// Opens a [`Daead`] keyring from the given `data` and validates the
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
    /// use navajo::daead::{ Daead, Algorithm };
    /// use navajo::envelope::InMemory;
    ///
    /// let daead = Daead::new(Algorithm::Aes256Siv, None);
    /// let primary_key = daead.primary_key();
    /// // in a real application, you would use a real key management service.
    /// // InMemory is only suitable for testing.
    /// let in_mem = InMemory::default();
    /// let data = Daead::seal_sync(Aad(&b"associated data"), &daead, &in_mem).unwrap();
    /// let daead = Daead::open_sync(Aad(&b"associated data"), &data, &in_mem).unwrap();
    /// assert_eq!(daead.primary_key(), primary_key);
    /// ```
    pub fn open_sync<A, E, C>(aad: Aad<A>, ciphertext: C, envelope: &E) -> Result<Self, OpenError>
    where
        A: AsRef<[u8]>,
        C: AsRef<[u8]>,
        E: 'static + crate::envelope::sync::Envelope,
    {
        let primitive = Primitive::open_sync(aad, ciphertext, envelope)?;
        if let Some(daead) = primitive.daead() {
            Ok(daead)
        } else {
            Err(OpenError("primitive is not a daead".into()))
        }
    }
    /// Seals an [`Daead`] keyring and tags it with `aad` for future
    /// authenticationby means of the [`Envelope`].
    ///
    /// # Errors
    /// Errors if the keyring could not be sealed by the [`Envelope`].
    ///
    /// # Example
    /// ```rust
    /// use navajo::Aad;
    /// use navajo::daead::{ Daead, Algorithm };
    /// use navajo::envelope::InMemory;
    ///
    /// #[tokio::main]
    /// async fn main() {
    ///     let daead = Daead::new(Algorithm::Aes256Siv, None);
    ///     let primary_key = daead.primary_key();
    ///     // in a real application, you would use a real key management service.
    ///     // InMemory is only suitable for testing.
    ///     let in_mem = InMemory::default();
    ///     let data = Daead::seal(Aad::empty(), &daead, &in_mem).await.unwrap();
    ///     let daead = Daead::open(Aad::empty(), data, &in_mem).await.unwrap();
    ///     assert_eq!(daead.primary_key(), primary_key);
    /// }
    /// ```
    pub async fn seal<A, E>(aad: Aad<A>, daead: &Self, envelope: &E) -> Result<Vec<u8>, SealError>
    where
        A: 'static + AsRef<[u8]> + Send + Sync,
        E: Envelope + 'static,
    {
        Primitive::Daead(daead.clone()).seal(aad, envelope).await
    }
    /// Seals a [`Daead`] keyring and tags it with `aad` for future
    /// authenticationby means of the [`Envelope`].
    ///
    /// # Errors
    /// Errors if the keyring could not be sealed by the [`Envelope`].
    ///
    /// # Example
    /// ```rust
    /// use navajo::Aad;
    /// use navajo::daead::{ Daead, Algorithm };
    /// use navajo::envelope::InMemory;
    ///
    /// let daead = Daead::new(Algorithm::Aes256Siv, None);
    /// let primary_key = daead.primary_key();
    /// // in a real application, you would use a real key management service.
    /// // InMemory is only suitable for testing.
    /// let in_mem = InMemory::default();
    /// let ciphertext = Daead::seal_sync(Aad::empty(), &daead, &in_mem).unwrap();
    /// let daead = Daead::open_sync(Aad::empty(), ciphertext, &in_mem).unwrap();
    /// assert_eq!(daead.primary_key(), primary_key);
    /// ```
    pub fn seal_sync<A, E>(aad: Aad<A>, daead: &Self, envelope: &E) -> Result<Vec<u8>, SealError>
    where
        A: AsRef<[u8]>,
        E: 'static + crate::envelope::sync::Envelope,
    {
        Primitive::Daead(daead.clone()).seal_sync(aad, envelope)
    }

    pub fn new(algorithm: Algorithm, metadata: Option<Metadata>) -> Self {
        Self::create(&SystemRng, algorithm, metadata)
    }

    fn create<N>(rng: &N, algorithm: Algorithm, metadata: Option<Metadata>) -> Self
    where
        N: Rng,
    {
        let id = rng.u32().unwrap();
        let material = Material::generate(rng, algorithm);
        let key = Key::new(id, Status::Primary, Origin::Navajo, material, metadata);
        let keyring = Keyring::new(key);
        Self { keyring }
    }

    pub(crate) fn keyring(&self) -> &Keyring<Material> {
        &self.keyring
    }
    pub(crate) fn from_keyring(keyring: Keyring<Material>) -> Self {
        Self { keyring }
    }

    pub fn keys(&self) -> Vec<KeyInfo> {
        self.keyring.keys().iter().map(Into::into).collect()
    }

    pub fn info(&self) -> KeyringInfo {
        KeyringInfo {
            keys: self.keys(),
            version: self.keyring().version,
            kind: crate::primitive::Kind::Daead,
        }
    }

    pub fn encrypt_in_place_deterministically<A, B>(
        &self,
        aad: Aad<A>,
        plaintext: &mut B,
    ) -> Result<(), EncryptDeterministicallyError>
    where
        A: AsRef<[u8]>,
        B: Buffer,
    {
        self.keyring
            .primary()
            .encrypt_in_place_deterministically(aad, plaintext)
    }
    /// Encrypts the given plaintext deterministically for each enabled key
    /// within the keyring for queries.
    pub fn encrypt_for_query_deterministically<A>(
        &self,
        aad: Aad<A>,
        plaintext: &[u8],
    ) -> Result<Vec<Vec<u8>>, EncryptDeterministicallyError>
    where
        A: AsRef<[u8]>,
    {
        let plaintext = plaintext.to_vec();
        let mut ciphertexts = Vec::new();
        let aad = Aad(aad.0.as_ref());
        for key in self
            .keyring
            .keys()
            .iter()
            .rev()
            .filter(|k| k.status().is_enabled())
        {
            ciphertexts.push(key.encrypt_deterministically(aad, &plaintext)?);
        }
        Ok(ciphertexts)
    }

    pub fn encrypt_deterministically(
        &self,
        aad: Aad<&[u8]>,
        plaintext: &[u8],
    ) -> Result<Vec<u8>, EncryptDeterministicallyError> {
        self.keyring
            .primary()
            .encrypt_deterministically(aad, plaintext)
    }

    pub fn decrypt_deterministically(
        &self,
        aad: Aad<&[u8]>,
        ciphertext: &[u8],
    ) -> Result<Vec<u8>, crate::error::DecryptDeterministicallyError> {
        let mut buf = ciphertext.to_vec();
        self.decrypt_in_place_deterministically(aad, &mut buf)?;
        Ok(buf)
    }

    pub fn decrypt_in_place_deterministically<A, B>(
        &self,
        aad: Aad<A>,
        ciphertext: &mut B,
    ) -> Result<(), crate::error::DecryptDeterministicallyError>
    where
        A: AsRef<[u8]>,
        B: Buffer,
    {
        if ciphertext.len() < 4 {
            return Err(crate::error::DecryptDeterministicallyError::CiphertextTooShort);
        }

        let mut id_bytes = ciphertext.split_off(4);

        core::mem::swap(ciphertext, &mut id_bytes);
        let id = u32::from_be_bytes(id_bytes.as_ref().try_into().unwrap()); // safe: len checked above
        let key = self.keyring.get(id)?;
        key.decrypt_in_place_deterministically(aad, ciphertext)
    }

    pub fn add(&mut self, algorithm: Algorithm, metadata: Option<Metadata>) -> KeyInfo {
        let material = Material::generate(&SystemRng, algorithm);
        let id = self.keyring.next_id(&SystemRng);
        let key = Key::new(id, Status::Active, Origin::Navajo, material, metadata);
        self.keyring.add(key);
        self.keyring.last().into()
    }

    pub fn promote(&mut self, key_id: impl Into<u32>) -> Result<KeyInfo, KeyNotFoundError> {
        self.keyring.promote(key_id).map(Into::into)
    }

    pub fn enable(&mut self, key_id: impl Into<u32>) -> Result<KeyInfo, KeyNotFoundError> {
        self.keyring.enable(key_id).map(Into::into)
    }

    pub fn disable(&mut self, key_id: u32) -> Result<KeyInfo, DisableKeyError> {
        self.keyring.disable(key_id).map(Into::into)
    }

    pub fn delete(&mut self, key_id: impl Into<u32>) -> Result<KeyInfo, RemoveKeyError> {
        self.keyring.remove(key_id).map(Into::into)
    }
    /// Sets the metadata for the given key and returns the previous metadata if it exists.
    pub fn set_key_metadata(
        &mut self,
        key_id: u32,
        metadata: Option<Metadata>,
    ) -> Result<Option<Metadata>, KeyNotFoundError> {
        self.keyring.update_key_metadata(key_id, metadata)
    }

    /// Returns [`KeyInfo<Algorithm>`] for the primary key.
    pub fn primary_key(&self) -> KeyInfo {
        self.keyring.primary().into()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encrypt_decrypt_deterministically() {
        let mut daead = Daead::new(Algorithm::Aes256Siv, None);
        let primary_key = daead.keyring().primary();
        let plaintext = b"hello world test";
        let aad = Aad(b"my aad".as_ref());
        let ciphertext = daead.encrypt_deterministically(aad, plaintext).unwrap();

        assert_eq!(primary_key.id().to_be_bytes(), &ciphertext[..4]);

        let decrypted = daead.decrypt_deterministically(aad, &ciphertext).unwrap();
        assert_eq!(plaintext, &decrypted[..]);
        {
            let new_key = daead.add(Algorithm::Aes256Siv, None).id;
            daead.promote(new_key).unwrap();
        }

        let decrypted = daead.decrypt_deterministically(aad, &ciphertext).unwrap();
        assert_eq!(plaintext, &decrypted[..]);
    }

    #[test]
    fn test_encrypt_decrypt_query_deterministically() {
        let mut daead = Daead::new(Algorithm::Aes256Siv, None);
        daead.add(Algorithm::Aes256Siv, None);
        {
            let new_key = daead.add(Algorithm::Aes256Siv, None).id;
            daead.promote(new_key).unwrap();
        }

        let plaintext = b"hello world test";
        let aad = Aad(b"my aad".as_ref());
        let ciphertexts = daead
            .encrypt_for_query_deterministically(aad, plaintext)
            .unwrap();
        assert_eq!(ciphertexts.len(), 3);
        for ciphertext in ciphertexts {
            let decrypted = daead.decrypt_deterministically(aad, &ciphertext).unwrap();
            assert_eq!(plaintext, &decrypted[..]);
        }
    }
}
