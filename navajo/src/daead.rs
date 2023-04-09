#![doc = include_str!("./daead/README.md")]

mod algorithm;
mod cipher;
mod material;

pub use algorithm::Algorithm;
pub(crate) use material::Material;

use crate::{
    error::{DisableKeyError, EncryptDeterministicallyError, KeyNotFoundError, RemoveKeyError},
    key::Key,
    keyring::Keyring,
    Aad, Buffer, KeyInfo, Metadata, Origin, Rng, Status, SystemRng,
};
use alloc::{sync::Arc, vec::Vec};
use zeroize::ZeroizeOnDrop;

#[derive(Clone, Debug, ZeroizeOnDrop)]
pub struct Daead {
    keyring: Keyring<Material>,
}

impl Daead {
    pub fn new(algorithm: Algorithm, metadata: Option<Metadata>) -> Self {
        Self::create(&SystemRng, algorithm, metadata)
    }

    fn create<N>(rng: &N, algorithm: Algorithm, metadata: Option<Metadata>) -> Self
    where
        N: Rng,
    {
        let id = rng.u32().unwrap();
        let material = Material::generate(rng, algorithm);
        let metadata = metadata.map(Arc::new);
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

    pub fn keys(&self) -> Vec<KeyInfo<crate::daead::Algorithm>> {
        self.keyring.keys().iter().map(|k| k.info()).collect()
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

    pub fn add(&mut self, algorithm: Algorithm, metadata: Option<Metadata>) -> KeyInfo<Algorithm> {
        let material = Material::generate(&SystemRng, algorithm);
        let id = self.keyring.next_id(&SystemRng);
        let metadata = metadata.map(Arc::new);
        let key = Key::new(id, Status::Primary, Origin::Navajo, material, metadata);
        self.keyring.add(key);
        self.keyring.last().into()
    }

    pub fn promote(
        &mut self,
        key_id: impl Into<u32>,
    ) -> Result<KeyInfo<Algorithm>, KeyNotFoundError> {
        self.keyring.promote(key_id).map(|key| key.info())
    }

    pub fn enable(
        &mut self,
        key_id: impl Into<u32>,
    ) -> Result<KeyInfo<Algorithm>, KeyNotFoundError> {
        self.keyring.enable(key_id).map(|key| key.info())
    }

    pub fn disable(
        &mut self,
        key_id: u32,
    ) -> Result<KeyInfo<Algorithm>, DisableKeyError<Algorithm>> {
        self.keyring.disable(key_id).map(|key| key.info())
    }

    pub fn delete(
        &mut self,
        key_id: impl Into<u32>,
    ) -> Result<KeyInfo<Algorithm>, RemoveKeyError<Algorithm>> {
        self.keyring.remove(key_id).map(|k| k.info())
    }

    pub fn set_key_metadata(
        &mut self,
        key_id: u32,
        metadata: Option<Metadata>,
    ) -> Result<KeyInfo<Algorithm>, KeyNotFoundError> {
        self.keyring.update_key_metadata(key_id, metadata)?;
        let key = self.keyring.get(key_id)?;
        Ok(key.info())
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
            let new_key = daead.add(Algorithm::Aes256Siv, None);
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
            let new_key = daead.add(Algorithm::Aes256Siv, None);
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
