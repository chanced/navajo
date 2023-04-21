#![doc = include_str!("./aead/README.md")]
mod algorithm;
mod backend;
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
    envelope,
    error::{EncryptError, KeyNotFoundError, OpenError, RemoveKeyError, SealError},
    key::Key,
    keyring::Keyring,
    rand::Rng,
    Buffer, Envelope, Metadata, Origin, Primitive, Status, SystemRng,
};
use alloc::boxed::Box;
#[cfg(not(feature = "std"))]
use alloc::vec::Vec;
use core::mem;
use futures::{Stream, TryStream};
pub(crate) use material::Material;
use size::Size;
use zeroize::ZeroizeOnDrop;

pub use crate::aad::Aad;

pub use self::key_info::{KeyInfo, KeyringInfo};
pub use algorithm::Algorithm;
pub use ciphertext_info::CiphertextInfo;
pub use decryptor::Decryptor;
pub use encryptor::Encryptor;
pub use method::Method;
pub use segment::Segment;
pub use stream::{AeadStream, DecryptStream, EncryptStream};
pub use try_stream::{AeadTryStream, DecryptTryStream, EncryptTryStream};

#[cfg(feature = "std")]
mod reader;
#[cfg(feature = "std")]
mod writer;
#[cfg(feature = "std")]
pub use reader::DecryptReader;
#[cfg(feature = "std")]
pub use writer::EncryptWriter;

/// Authenticated Encryption with Associated Data (AEAD)
#[derive(Clone, Debug, ZeroizeOnDrop)]
pub struct Aead {
    keyring: Keyring<Material>,
}
impl Aead {
    /// Opens an [`Aead`] keyring from the given `data` and validates the
    /// authenticity with `aad` by means of the [`Envelope`] `envelope`.
    ///
    /// # Errors
    /// Errors if the keyring could not be opened by the or the authenticity
    /// could not be verified by the [`Envelope`] using futures.
    ///
    /// # Example
    /// ```rust
    /// use navajo::Aad;
    /// use navajo::aead::{ Aead, Algorithm };
    /// use navajo::envelope::InMemory;
    ///
    /// #[tokio::main]
    /// async fn main() {
    ///     let aead = Aead::new(Algorithm::ChaCha20Poly1305, None);
    ///     let primary_key = aead.primary_key();
    ///     // in a real application, you would use a real key management service.
    ///     // InMemory is only suitable for testing.
    ///     let in_mem = InMemory::default();
    ///     let data = Aead::seal(Aad::empty(), &aead, &in_mem).await.unwrap();
    ///     let aead = Aead::open(Aad::empty(), data, &in_mem).await.unwrap();
    ///     assert_eq!(aead.primary_key(), primary_key);
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
            .aead()
            .ok_or(OpenError("primitive is not Aead".into()))
    }

    /// Opens an [`Aead`] keyring from the given `data` and validates the
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
    /// use navajo::aead::{ Aead, Algorithm };
    /// use navajo::envelope::InMemory;
    ///
    /// let aead = Aead::new(Algorithm::Aes256Gcm, None);
    /// let primary_key = aead.primary_key();
    /// // in a real application, you would use a real key management service.
    /// // InMemory is only suitable for testing.
    /// let in_mem = InMemory::default();
    /// let data = Aead::seal_sync(Aad(&b"associated data"), &aead, &in_mem).unwrap();
    /// let aead = Aead::open_sync(Aad(&b"associated data"), &data, &in_mem).unwrap();
    /// assert_eq!(aead.primary_key(), primary_key);
    /// ```
    pub fn open_sync<A, E, C>(aad: Aad<A>, ciphertext: C, envelope: &E) -> Result<Self, OpenError>
    where
        A: AsRef<[u8]>,
        C: AsRef<[u8]>,
        E: 'static + crate::envelope::sync::Envelope,
    {
        let primitive = Primitive::open_sync(aad, ciphertext, envelope)?;
        if let Some(aead) = primitive.aead() {
            Ok(aead)
        } else {
            Err(OpenError("primitive is not a aead".into()))
        }
    }
    /// Seals an [`Aead`] keyring and tags it with `aad` for future
    /// authenticationby means of the [`Envelope`].
    ///
    /// # Errors
    /// Errors if the keyring could not be sealed by the [`Envelope`].
    ///
    /// # Example
    /// ```rust
    /// use navajo::Aad;
    /// use navajo::aead::{ Aead, Algorithm };
    /// use navajo::envelope::InMemory;
    ///
    /// #[tokio::main]
    /// async fn main() {
    ///     let aead = Aead::new(Algorithm::Aes256Gcm, None);
    ///     let primary_key = aead.primary_key();
    ///     // in a real application, you would use a real key management service.
    ///     // InMemory is only suitable for testing.
    ///     let in_mem = InMemory::default();
    ///     let data = Aead::seal(Aad::empty(), &aead, &in_mem).await.unwrap();
    ///     let aead = Aead::open(Aad::empty(), data, &in_mem).await.unwrap();
    ///     assert_eq!(aead.primary_key(), primary_key);
    /// }
    /// ```
    pub async fn seal<A, E>(aad: Aad<A>, aead: &Self, envelope: &E) -> Result<Vec<u8>, SealError>
    where
        A: 'static + AsRef<[u8]> + Send + Sync,
        E: Envelope + 'static,
    {
        Primitive::Aead(aead.clone()).seal(aad, envelope).await
    }
    /// Seals a [`Aead`] keyring and tags it with `aad` for future
    /// authenticationby means of the [`Envelope`].
    ///
    /// # Errors
    /// Errors if the keyring could not be sealed by the [`Envelope`].
    ///
    /// # Example
    /// ```rust
    /// use navajo::Aad;
    /// use navajo::aead::{ Aead, Algorithm };
    /// use navajo::envelope::InMemory;
    ///
    /// let aead = Aead::new(Algorithm::Aes256Gcm, None);
    /// let primary_key = aead.primary_key();
    /// // in a real application, you would use a real key management service.
    /// // InMemory is only suitable for testing.
    /// let in_mem = InMemory::default();
    /// let ciphertext = Aead::seal_sync(Aad::empty(), &aead, &in_mem).unwrap();
    /// let aead = Aead::open_sync(Aad::empty(), ciphertext, &in_mem).unwrap();
    /// assert_eq!(aead.primary_key(), primary_key);
    /// ```
    pub fn seal_sync<A, E>(aad: Aad<A>, aead: &Self, envelope: &E) -> Result<Vec<u8>, SealError>
    where
        A: AsRef<[u8]>,
        E: 'static + crate::envelope::sync::Envelope,
    {
        Primitive::Aead(aead.clone()).seal_sync(aad, envelope)
    }

    /// Creates a new AEAD keyring with a single key of the given algorithm with
    /// the provided metadata.
    pub fn new(algorithm: Algorithm, metadata: Option<Metadata>) -> Self {
        Self::create(&SystemRng, algorithm, metadata)
    }

    #[cfg(test)]
    pub fn new_with_rng<N>(rng: &N, algorithm: Algorithm, metadata: Option<Metadata>) -> Self
    where
        N: Rng,
    {
        Self::create(rng, algorithm, metadata)
    }
    /// Encrypts the given plaintext with `aad` as additional authenticated
    /// data. The resulting ciphertext replaces the contents of `plaintext`.
    /// Note that `aad` is not encrypted and is merely used for authentication.
    /// As such, there are no secrecy gaurantees for `aad`.
    ///
    /// # Errors
    /// Returns an [`EncryptError`] under the following conditions:
    /// - `plaintext` is empty
    /// - the backend fails to encrypt the plaintext
    ///
    /// # Example
    /// ```
    /// use navajo::aead::{Aead, Algorithm};
    /// use navajo::Aad;
    /// let aead = Aead::new(Algorithm::Aes256Gcm, None);
    /// let mut data = b"Hello, world!".to_vec();
    /// aead.encrypt_in_place(Aad::empty(), &mut data).unwrap();
    /// assert_ne!(&data, &b"Hello, world!");
    /// ```
    pub fn encrypt_in_place<A, T>(&self, aad: Aad<A>, plaintext: &mut T) -> Result<(), EncryptError>
    where
        A: AsRef<[u8]>,
        T: Buffer,
    {
        let encryptor = Encryptor::new(SystemRng, self, None, mem::take(plaintext));
        let result = encryptor
            .finalize(aad)?
            .next()
            .ok_or(EncryptError::Unspecified)?;
        *plaintext = result;
        Ok(())
    }
    /// Encrypts the given plaintext with `aad` as additional authenticated
    /// data. The resulting ciphertext is returned. Note that `aad` is not
    /// encrypted and is merely used for authentication. As such, there are no
    /// secrecy gaurantees for `aad`.
    ///
    /// # Errors
    /// Returns an [`EncryptError`] under the following conditions:
    /// - `plaintext` is empty
    /// - the backend fails to encrypt the plaintext
    ///
    /// # Example
    /// ```
    /// use navajo::aead::{Aead, Algorithm};
    /// use navajo::Aad;
    /// let aead = Aead::new(Algorithm::Aes256Gcm, None);
    /// let mut data = b"Hello, world!".to_vec();
    /// let ciphertext = aead.encrypt(Aad::empty(), &mut data).unwrap();
    /// assert_ne!(&data, &ciphertext);
    /// ```
    pub fn encrypt<A, T>(&self, aad: Aad<A>, plaintext: T) -> Result<Vec<u8>, EncryptError>
    where
        A: AsRef<[u8]>,
        T: AsRef<[u8]>,
    {
        let encryptor = Encryptor::new(SystemRng, self, None, plaintext.as_ref().to_vec());
        let result = encryptor
            .finalize(aad)?
            .next()
            .ok_or(EncryptError::Unspecified)?;
        Ok(result)
    }

    /// Returns a new [`EncryptStream`] which encrypts data using either STREAM
    /// as desribed in [Online Authenticated-Encryption and its Nonce-Reuse
    /// Misuse-Resistance](https://eprint.iacr.org/2015/189.pdf) if the
    /// finalized ciphertext is greater than the specified [`Segment`] as
    /// described in [RFC 5116](https://tools.ietf.org/html/rfc5116) with an 5
    /// byte header. Otherwise traditional "online" AEAD encryption is used.
    ///
    /// [`Aad`] `aad` is used for authentication and is not encrypted. As such, there
    /// are no secrecy gaurantees for `aad`.
    ///
    /// If the resulting ciphertext is greater than [`Segment`], the header will
    /// be in the form:
    ///
    /// ```plaintext
    /// || Method (1) || Key Id (4) || Salt (variable) || Nonce Prefix (variable) ||
    /// ```
    /// where `Salt` is the length of the algorithm's key and `Nonce Prefix` is
    /// the length of the algorithm's nonce minus 5 bytes (4 for the segment
    /// counter & 1 byte for the last-block flag).
    ///
    /// If the resulting ciphertext is less than [`Segment`], the header will be
    /// in the form:
    /// ```plaintext
    /// || Method (1) || Key Id (4) || Nonce (variable) ||
    /// ```
    ///
    /// If the resulting ciphertext is greater than [`Segment`] then each
    /// segment block will be be of the size specified by [`Segment`] except for
    /// the last, which will be no greater than [`Segment`].
    ///
    /// # Example
    /// ```
    /// use navajo::aead::{Aead, Algorithm, Segment};
    /// use navajo::Aad;
    /// use futures::{stream, TryStreamExt};
    ///
    /// #[tokio::main]
    /// async fn main() {
    ///     let aead = Aead::new(Algorithm::ChaCha20Poly1305, None);
    ///     let data = stream::iter(vec![
    ///         Vec::from("hello".as_bytes()),
    ///         Vec::from(" ".as_bytes()),
    ///         Vec::from("world".as_bytes()),
    ///     ]);
    ///     let enc_stream = aead.encrypt_stream(data, Aad::empty(), Segment::FourKilobytes);
    ///     let ciphertext: Vec<u8> = enc_stream.try_concat().await.unwrap();
    ///     assert_ne!(&ciphertext, &b"hello world");
    /// }
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
        EncryptStream::new(SystemRng, stream, segment, aad, self)
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
        EncryptTryStream::new(SystemRng, stream, segment, aad, self)
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
        let mut writer = EncryptWriter::new(SystemRng, writer, segment, aad, self);
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
    pub fn decrypt_stream<S, A>(&self, stream: S, aad: Aad<A>) -> DecryptStream<S, Self, A>
    where
        S: Stream,
        S::Item: AsRef<[u8]>,
        A: AsRef<[u8]> + Send + Sync,
    {
        DecryptStream::new(SystemRng, stream, self.clone(), aad)
    }

    pub fn decrypt_try_stream<S, A>(&self, stream: S, aad: Aad<A>) -> DecryptTryStream<S, Self, A>
    where
        S: TryStream,
        S::Ok: AsRef<[u8]>,
        S::Error: Send + Sync,
        A: AsRef<[u8]> + Send + Sync,
    {
        DecryptTryStream::new(stream, self.clone(), aad)
    }

    #[cfg(feature = "std")]
    pub fn decrypt_reader<N, A>(&self, reader: N, aad: Aad<A>) -> DecryptReader<N, A, &Self>
    where
        N: std::io::Read,
        A: AsRef<[u8]>,
    {
        DecryptReader::new(reader, aad, self)
    }

    pub(crate) fn from_keyring(keyring: Keyring<Material>) -> Self {
        Self { keyring }
    }

    /// Returns a [`Vec`] containing [`AeadKeyInfo`] for each key in this
    /// keyring.
    pub fn keys(&self) -> Vec<KeyInfo> {
        self.keyring.keys().iter().map(Into::into).collect()
    }

    /// Returns [`AeadKeyInfo`] for the primary key.
    pub fn primary_key(&self) -> KeyInfo {
        self.keyring.primary().into()
    }

    pub fn promote(
        &mut self,
        key_id: impl Into<u32>,
    ) -> Result<KeyInfo, crate::error::KeyNotFoundError> {
        self.keyring.promote(key_id).map(Into::into)
    }

    pub fn add(&mut self, algorithm: Algorithm, metadata: Option<Metadata>) -> KeyInfo {
        let id = self.keyring.next_id(&SystemRng);
        let material = Material::generate(&SystemRng, algorithm);
        let key = Key::new(id, Status::Secondary, Origin::Navajo, material, metadata);
        self.keyring.add(key).into()
    }
    pub fn disable(
        &mut self,
        key_id: impl Into<u32>,
    ) -> Result<KeyInfo, crate::error::DisableKeyError> {
        self.keyring.disable(key_id).map(Into::into)
    }

    pub fn enable(&mut self, key_id: impl Into<u32>) -> Result<KeyInfo, KeyNotFoundError> {
        self.keyring.enable(key_id).map(Into::into)
    }

    pub fn delete(&mut self, key_id: impl Into<u32>) -> Result<KeyInfo, RemoveKeyError> {
        self.keyring.remove(key_id).map(Into::into)
    }
    /// Sets the metadata for the key with the given ID, returning the previous [`Metadata`] if it exists.
    pub fn set_key_metadata(
        &mut self,
        key_id: impl Into<u32>,
        meta: Option<Metadata>,
    ) -> Result<Option<Metadata>, KeyNotFoundError> {
        self.keyring.update_key_metadata(key_id, meta)
    }

    pub(crate) fn keyring(&self) -> &Keyring<Material> {
        &self.keyring
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
    pub fn info(&self) -> KeyringInfo {
        KeyringInfo {
            keys: self.keys(),
            version: self.keyring().version,
            kind: crate::primitive::Kind::Aead,
        }
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

    fn encrypt_dek<A, P>(
        &self,
        aad: Aad<A>,
        plaintext: P,
    ) -> core::pin::Pin<
        Box<dyn futures::Future<Output = Result<Vec<u8>, Self::EncryptError>> + Send + '_>,
    >
    where
        A: 'static + AsRef<[u8]> + Send + Sync,
        P: 'static + AsRef<[u8]> + Send + Sync,
    {
        Box::pin(async move { self.encrypt(aad, plaintext) })
    }

    fn decrypt_dek<A, B>(
        &self,
        aad: Aad<A>,
        ciphertext: B,
    ) -> core::pin::Pin<
        Box<dyn futures::Future<Output = Result<Vec<u8>, Self::DecryptError>> + Send + '_>,
    >
    where
        A: 'static + AsRef<[u8]> + Send + Sync,
        B: 'static + AsRef<[u8]> + Send + Sync,
    {
        Box::pin(async move { self.decrypt(aad, ciphertext) })
    }
}

impl envelope::sync::Envelope for Aead {
    type EncryptError = crate::error::EncryptError;
    type DecryptError = crate::error::DecryptError;
    fn encrypt_dek<A, P>(&self, aad: Aad<A>, plaintext: P) -> Result<Vec<u8>, Self::EncryptError>
    where
        A: AsRef<[u8]>,
        P: AsRef<[u8]>,
    {
        self.encrypt(aad, plaintext)
    }
    fn decrypt_dek<A, C>(&self, aad: Aad<A>, ciphertext: C) -> Result<Vec<u8>, Self::DecryptError>
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
    fn encrypt_decrypt(mut plaintext: Vec<u8>, aad: Vec<u8>) -> bool {
        for algorithm in Algorithm::iter() {
            let src = plaintext.clone();
            let aead = Aead::new(algorithm, None);
            let result = aead.encrypt_in_place(Aad(&aad), &mut plaintext);
            if plaintext.is_empty() {
                if result.is_ok() {
                    return false;
                } else {
                    continue;
                }
            }
            if aead.decrypt_in_place(Aad(&aad), &mut plaintext).is_err() {
                return false;
            }
            if src != plaintext {
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
