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

use crate::{
    error::{EncryptError, KeyNotFoundError, RemoveKeyError},
    keyring::Keyring,
    Aad, Buffer,
};
use alloc::vec::Vec;
use core::mem;
use futures::{Stream, TryStream};
pub(crate) use material::Material;
use serde_json::Value;

use size::Size;
use zeroize::ZeroizeOnDrop;

pub use algorithm::Algorithm;
pub use ciphertext_info::CiphertextInfo;
pub use decryptor::Decryptor;
pub use encryptor::Encryptor;
pub use key_info::AeadKeyInfo;
pub use method::Method;
pub use segment::Segment;
pub use stream::{AeadStream, DecryptStream, EncryptStream};
pub use try_stream::{AeadTryStream, DecryptTryStream, EncryptTryStream};
cfg_if::cfg_if! {
    if #[cfg(feature = "std")] {
        mod reader;
        mod writer;
        pub use reader::DecryptReader;
        pub use writer::EncryptWriter;
    }
}

// use cipher::{ciphers, ring_ciphers, Cipher};

#[derive(Clone, Debug, ZeroizeOnDrop)]
pub struct Aead {
    keyring: Keyring<Material>,
}
impl Aead {
    pub fn new(algorithm: Algorithm, meta: Option<Value>) -> Self {
        Self {
            keyring: Keyring::new(Material::new(algorithm), crate::Origin::Navajo, meta),
        }
    }

    pub(crate) fn from_keyring(keyring: Keyring<Material>) -> Self {
        Self { keyring }
    }
    pub fn encrypt_in_place<B, A>(&self, aad: Aad<A>, data: &mut B) -> Result<(), EncryptError>
    where
        A: AsRef<[u8]>,
        B: Buffer,
    {
        let encryptor = Encryptor::new(self, None, mem::take(data));
        let result = encryptor
            .finalize(aad)?
            .next()
            .ok_or(EncryptError::Unspecified)?;
        *data = result;
        Ok(())
    }

    pub fn encrypt<A, B>(&self, aad: Aad<A>, data: B) -> Result<Vec<u8>, EncryptError>
    where
        A: AsRef<[u8]>,
        B: AsRef<[u8]>,
    {
        let encryptor = Encryptor::new(self, None, data.as_ref().to_vec());
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

    pub fn decrypt_in_place<A, B>(
        &self,
        aad: Aad<A>,
        data: &mut B,
    ) -> Result<(), crate::error::DecryptError>
    where
        A: AsRef<[u8]>,
        B: Buffer,
    {
        let decryptor = Decryptor::new(self, mem::take(data));
        let result = decryptor
            .finalize(aad)?
            .next()
            .ok_or(crate::error::DecryptError::Unspecified)?;
        *data = result;
        Ok(())
    }

    pub fn decrypt<A, C>(
        &self,
        aad: Aad<A>,
        cleartext: C,
    ) -> Result<Vec<u8>, crate::error::DecryptError>
    where
        A: AsRef<[u8]>,
        C: AsRef<[u8]>,
    {
        let data = cleartext.as_ref().to_vec();
        let decryptor = Decryptor::new(self, data);
        let mut result = Vec::new();
        for segment in decryptor.finalize(aad)? {
            result.extend_from_slice(&segment);
        }
        Ok(result)
    }

    pub fn decrypt_steram<S, A>(&self, stream: S, aad: Aad<A>) -> DecryptStream<S, Aead, A>
    where
        S: Stream,
        S::Item: AsRef<[u8]>,
        A: AsRef<[u8]> + Send + Sync,
    {
        DecryptStream::new(stream, self.clone(), aad)
    }

    pub fn decrypt_try_steram<S, A>(&self, stream: S, aad: Aad<A>) -> DecryptTryStream<S, Aead, A>
    where
        S: TryStream,
        S::Ok: AsRef<[u8]>,
        S::Error: Send + Sync,
        A: AsRef<[u8]> + Send + Sync,
    {
        DecryptTryStream::new(stream, self.clone(), aad)
    }

    pub fn decrypt_reader<R, A>(&self, reader: R, aad: Aad<A>) -> DecryptReader<R, A, &Aead>
    where
        R: std::io::Read,
        A: AsRef<[u8]>,
    {
        DecryptReader::new(reader, aad, self)
    }

    /// Returns a [`Vec`] containing [`AeadKeyInfo`] for each key in this
    /// keyring.
    pub fn keys(&self) -> Vec<AeadKeyInfo> {
        self.keyring.keys().iter().map(AeadKeyInfo::new).collect()
    }

    pub fn add_key(&mut self, algorithm: Algorithm, meta: Option<Value>) -> &mut Self {
        self.keyring
            .add(Material::new(algorithm), crate::Origin::Navajo, meta);
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
impl AsRef<Aead> for Aead {
    fn as_ref(&self) -> &Aead {
        self
    }
}

impl AsMut<Aead> for Aead {
    fn as_mut(&mut self) -> &mut Aead {
        self
    }
}

#[cfg(test)]
mod tests {

    use super::*;

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
