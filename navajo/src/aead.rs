#![doc = include_str!("./aead/README.md")]
mod algorithm;
mod cipher;
mod ciphertext_info;
mod decryptor;
mod encryptor;
mod key_info;
mod material;
mod method;
mod nonce;
mod seed;
mod segment;
mod size;
mod stream;
mod try_stream;

#[cfg(feature = "hkdf")]
mod derived_aead;

use crate::{
    error::{EncryptError, KeyNotFoundError, RemoveKeyError},
    keyring::Keyring,
    rand::Rng,
    Aad, Buffer, Envelope, SystemRng,
};
#[cfg(not(feature = "std"))]
use alloc::vec::Vec;
use core::mem;
use futures::{Stream, TryStream};
use inherent::inherent;
pub(crate) use material::Material;
use serde_json::Value;
use size::Size;
use zeroize::{Zeroize, ZeroizeOnDrop};

pub use algorithm::Algorithm;
pub use ciphertext_info::CiphertextInfo;
pub use decryptor::Decryptor;
pub use encryptor::Encryptor;
pub use key_info::AeadKeyInfo;
pub use method::Method;
pub use segment::Segment;
pub use stream::{AeadStream, DecryptStream, EncryptStream};
pub use try_stream::{AeadTryStream, DecryptTryStream, EncryptTryStream};

#[cfg(feature = "hkdf")]
pub use derived_aead::DerivedAead;
#[cfg(feature = "std")]
mod reader;
#[cfg(feature = "std")]
mod writer;
#[cfg(feature = "std")]
pub use reader::DecryptReader;
#[cfg(feature = "std")]
pub use writer::EncryptWriter;

// use cipher::{ciphers, ring_ciphers, Cipher};

#[derive(Clone, Debug, ZeroizeOnDrop)]
pub struct Aead {
    keyring: Keyring<Material>,
}

impl Aead {
    pub fn encrypt_in_place<A, T>(&self, aad: Aad<A>, cleartext: &mut T) -> Result<(), EncryptError>
    where
        A: AsRef<[u8]>,
        T: Buffer,
    {
        let encryptor = Encryptor::new(self, None, mem::take(cleartext));
        let result = encryptor
            .finalize(aad)?
            .next()
            .ok_or(EncryptError::Unspecified)?;
        *cleartext = result;
        Ok(())
    }
    /// encrypt...
    pub fn encrypt<A, T>(&self, aad: Aad<A>, cleartext: T) -> Result<Vec<u8>, EncryptError>
    where
        A: AsRef<[u8]>,
        T: AsRef<[u8]>,
    {
        let encryptor = Encryptor::new(self, None, cleartext.as_ref().to_vec());
        let result = encryptor
            .finalize(aad)?
            .next()
            .ok_or(EncryptError::Unspecified)?;
        Ok(result)
    }

    pub fn encrypt_stream<S, A>(
        &self,
        stream: S,
        aad: Aad<A>,
        segment: Segment,
    ) -> EncryptStream<S, A>
    where
        S: Stream,
        S::Item: AsRef<[u8]>,
        A: AsRef<[u8]> + Send + Sync,
    {
        EncryptStream::new(stream, segment, aad, self)
    }

    pub fn encrypt_try_stream<S, A>(
        &self,
        stream: S,
        segment: Segment,
        aad: Aad<A>,
    ) -> EncryptTryStream<S, A>
    where
        S: TryStream,
        S::Ok: AsRef<[u8]>,
        S::Error: Send + Sync,
        A: AsRef<[u8]> + Send + Sync,
    {
        EncryptTryStream::new(stream, segment, aad, self)
    }

    #[cfg(feature = "std")]
    pub fn encrypt_writer<'w, F, W, A>(
        &self,
        writer: &'w mut W,
        aad: Aad<A>,
        segment: Segment,
        f: F,
    ) -> Result<usize, std::io::Error>
    where
        F: FnOnce(&mut EncryptWriter<'w, W, A>) -> Result<(), std::io::Error>,
        W: std::io::Write,
        A: 'w + AsRef<[u8]>,
    {
        let mut writer = EncryptWriter::new(writer, segment, aad, self);
        f(&mut writer)?;
        writer.finalize()
    }

    pub fn decrypt<A, T>(
        &self,
        aad: Aad<A>,
        ciphertext: T,
    ) -> Result<Vec<u8>, crate::error::DecryptError>
    where
        A: AsRef<[u8]>,
        T: AsRef<[u8]>,
    {
        let data = ciphertext.as_ref().to_vec();
        let decryptor = Decryptor::new(self, data);
        let mut result = Vec::new();
        for segment in decryptor.finalize(aad)? {
            result.extend_from_slice(&segment);
        }
        Ok(result)
    }

    pub fn decrypt_in_place<A, T>(
        &self,
        aad: Aad<A>,
        ciphertext: &mut T,
    ) -> Result<(), crate::error::DecryptError>
    where
        A: AsRef<[u8]>,
        T: Buffer,
    {
        let decryptor = Decryptor::new(self, mem::take(ciphertext));
        let result = decryptor
            .finalize(aad)?
            .next()
            .ok_or(crate::error::DecryptError::Unspecified)?;
        *ciphertext = result;
        Ok(())
    }
    pub fn decrypt_stream<S, A>(
        &self,
        stream: S,
        aad: Aad<A>,
    ) -> DecryptStream<S, Self, A, SystemRng>
    where
        S: Stream,
        S::Item: AsRef<[u8]>,
        A: AsRef<[u8]> + Send + Sync,
    {
        DecryptStream::new(stream, self.clone(), aad)
    }

    pub fn decrypt_try_stream<S, A>(
        &self,
        stream: S,
        aad: Aad<A>,
    ) -> DecryptTryStream<S, Self, A, SystemRng>
    where
        S: TryStream,
        S::Ok: AsRef<[u8]>,
        S::Error: Send + Sync,
        A: AsRef<[u8]> + Send + Sync,
    {
        DecryptTryStream::new(stream, self.clone(), aad)
    }

    #[cfg(feature = "std")]
    pub fn decrypt_reader<R, A>(
        &self,
        reader: R,
        aad: Aad<A>,
    ) -> DecryptReader<R, A, &Self, SystemRng>
    where
        R: std::io::Read,
        A: AsRef<[u8]>,
    {
        DecryptReader::new(reader, aad, self)
    }
}

impl Aead {
    pub fn new(algorithm: Algorithm, meta: Option<Value>) -> Self {
        Self::generate(&SystemRng, algorithm, meta)
    }
    #[cfg(test)]
    pub fn new_with_rng<G>(rng: &G, algorithm: Algorithm, meta: Option<Value>) -> Self
    where
        G: Rng,
    {
        Self::generate(rng, algorithm, meta)
    }
    fn generate<G>(rng: &G, algorithm: Algorithm, meta: Option<Value>) -> Self
    where
        G: Rng,
    {
        Self {
            keyring: Keyring::new(rng, Material::new(algorithm), crate::Origin::Navajo, meta),
        }
    }

    pub(crate) fn from_keyring(keyring: Keyring<Material>) -> Self {
        Self { keyring }
    }

    /// Returns a [`Vec`] containing [`AeadKeyInfo`] for each key in this
    /// keyring.
    pub fn keys(&self) -> Vec<AeadKeyInfo> {
        self.keyring.keys().iter().map(AeadKeyInfo::new).collect()
    }

    pub fn add_key(&mut self, algorithm: Algorithm, meta: Option<Value>) -> &mut Self {
        self.keyring.add(
            &SystemRng,
            Material::new(algorithm),
            crate::Origin::Navajo,
            meta,
        );
        self
    }

    /// Returns [`AeadKeyInfo`] for the primary key.
    pub fn primary_key(&self) -> AeadKeyInfo {
        self.keyring.primary().into()
    }

    pub fn promote_key(
        &mut self,
        key_id: impl Into<u32>,
    ) -> Result<AeadKeyInfo, crate::error::KeyNotFoundError> {
        self.keyring.promote(key_id).map(AeadKeyInfo::new)
    }

    pub fn disable_key(
        &mut self,
        key_id: impl Into<u32>,
    ) -> Result<AeadKeyInfo, crate::error::DisableKeyError<Algorithm>> {
        self.keyring.disable(key_id).map(AeadKeyInfo::new)
    }

    pub fn enable_key(&mut self, key_id: impl Into<u32>) -> Result<AeadKeyInfo, KeyNotFoundError> {
        self.keyring.enable(key_id).map(AeadKeyInfo::new)
    }

    pub fn remove_key(
        &mut self,
        key_id: impl Into<u32>,
    ) -> Result<AeadKeyInfo, RemoveKeyError<Algorithm>> {
        self.keyring.remove(key_id).map(|k| AeadKeyInfo::new(&k))
    }

    pub fn update_key_meta(
        &mut self,
        key_id: impl Into<u32>,
        meta: Option<Value>,
    ) -> Result<AeadKeyInfo, KeyNotFoundError> {
        self.keyring.update_meta(key_id, meta).map(AeadKeyInfo::new)
    }

    pub(crate) fn keyring(&self) -> &Keyring<Material> {
        &self.keyring
    }
}

impl AsMut<Aead> for Aead {
    fn as_mut(&mut self) -> &mut Aead {
        self
    }
}

impl Envelope for Aead {
    type EncryptError = crate::error::EncryptError;

    type DecryptError = crate::error::DecryptError;

    fn encrypt_dek<'a, A, P>(
        &'a self,
        aad: Aad<A>,
        cleartext: P,
    ) -> core::pin::Pin<
        Box<dyn futures::Future<Output = Result<Vec<u8>, Self::EncryptError>> + Send + '_>,
    >
    where
        A: 'a + AsRef<[u8]> + Send + Sync,
        P: 'a + AsRef<[u8]> + Send + Sync,
    {
        Box::pin(async move { self.encrypt(aad, cleartext) })
    }

    fn encrypt_dek_sync<A, P>(
        &self,
        aad: Aad<A>,
        cleartext: P,
    ) -> Result<Vec<u8>, Self::EncryptError>
    where
        A: AsRef<[u8]>,
        P: AsRef<[u8]>,
    {
        self.encrypt(aad, cleartext)
    }

    fn decrypt_dek<'a, A, B>(
        &'a self,
        aad: Aad<A>,
        ciphertext: B,
    ) -> core::pin::Pin<
        Box<dyn futures::Future<Output = Result<Vec<u8>, Self::DecryptError>> + Send + '_>,
    >
    where
        A: 'a + AsRef<[u8]> + Send + Sync,
        B: 'a + AsRef<[u8]> + Send + Sync,
    {
        Box::pin(async move { self.decrypt(aad, ciphertext) })
    }

    fn decrypt_dek_sync<A, C>(
        &self,
        aad: Aad<A>,
        ciphertext: C,
    ) -> Result<Vec<u8>, Self::DecryptError>
    where
        A: AsRef<[u8]>,
        C: AsRef<[u8]>,
    {
        self.decrypt(aad, ciphertext)
    }
}

impl AsRef<Aead> for Aead {
    fn as_ref(&self) -> &Aead {
        self
    }
}

#[cfg(test)]
mod tests {
    use quickcheck_macros::quickcheck;
    use strum::IntoEnumIterator;

    use super::*;

    #[quickcheck]
    fn encrypt_decrypt(mut cleartext: Vec<u8>, aad: Vec<u8>) -> bool {
        for algorithm in Algorithm::iter() {
            let src = cleartext.clone();
            let aead = Aead::new(algorithm, None);
            let result = aead.encrypt_in_place(Aad(&aad), &mut cleartext);
            if cleartext.is_empty() {
                if result.is_ok() {
                    return false;
                } else {
                    continue;
                }
            }
            if let Err(e) = aead.decrypt_in_place(Aad(&aad), &mut cleartext) {
                println!("{e:?}");
                return false;
            }
            if src != cleartext {
                return false;
            }
        }
        true
    }

    #[test]
    fn test_encrypt_in_place() {
        let aead = Aead::new(Algorithm::Aes256Gcm, None);
        let mut data = b"hello world".to_vec();
        aead.encrypt_in_place(Aad(b"additional data"), &mut data)
            .unwrap();
        assert_ne!(data, b"hello world");
        assert!(!data.is_empty());
    }
    #[test]
    fn test_decrypt_in_place() {
        let aead = Aead::new(Algorithm::Aes256Gcm, None);
        let mut data = b"hello world".to_vec();
        aead.encrypt_in_place(Aad(b"additional data"), &mut data)
            .unwrap();
        let aead = Aead::new(Algorithm::Aes256Gcm, None);
        let mut data = b"hello world".to_vec();
        aead.encrypt_in_place(Aad(b"additional data"), &mut data)
            .unwrap();
        assert_ne!(data, b"hello world");
        aead.decrypt_in_place(Aad(b"additional data"), &mut data)
            .unwrap();
        assert_eq!(data, b"hello world");
    }
    #[cfg(feature = "std")]
    #[test]
    fn test_encrypt_writer() {
        use std::io::Write;

        let mut writer = vec![];
        let aad = Aad(b"additional data");
        let aead = Aead::new(Algorithm::Aes256Gcm, None);
        let msg = b"hello world".to_vec();
        aead.encrypt_writer(&mut writer, Aad(aad), Segment::FourKilobytes, |w| {
            w.write_all(&msg)
        })
        .unwrap();

        let decryptor = Decryptor::new(&aead, writer);
        let result = decryptor.finalize(aad).unwrap().next().unwrap();
        assert_eq!(result, msg);
    }
}
