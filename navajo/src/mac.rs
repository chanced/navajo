#![doc = include_str!("./mac/README.md")]

mod algorithm;
mod computer;
mod context;
mod entry;
mod key_info;
mod material;
mod output;
mod stream;
mod tag;
mod try_stream;
mod verifier;

pub use algorithm::Algorithm;
pub use computer::Computer;
pub use key_info::MacKeyInfo;
pub use stream::{ComputeStream, MacStream, VerifyStream};
pub use tag::Tag;
pub use try_stream::{ComputeTryStream, MacTryStream, VerifyTryStream};
pub use verifier::Verifier;

pub(crate) use material::Material;

use crate::error::{
    KeyError, KeyNotFoundError, MacVerificationError, OpenError, RemoveKeyError, SealError,
};
use crate::key::Key;
use crate::primitive::Primitive;
use crate::rand::{Rng, SystemRng};
use crate::{Aad, Envelope, Keyring, Metadata, Origin, Status};
use alloc::sync::Arc;
use alloc::vec::Vec;
use context::*;
use futures::{Stream, TryStream};
use zeroize::ZeroizeOnDrop;

const SHA2_256_KEY_LEN: usize = 32;
const SHA2_384_KEY_LEN: usize = 48;
const SHA2_512_KEY_LEN: usize = 64;
const SHA3_224_KEY_LEN: usize = 32;
const SHA3_256_KEY_LEN: usize = 32;
const SHA3_384_KEY_LEN: usize = 48;
const SHA3_512_KEY_LEN: usize = 64;
#[cfg(feature = "blake3")]
const BLAKE3_KEY_LEN: usize = 32;
#[cfg(feature = "aes")]
const AES128_KEY_LEN: usize = 16;
#[cfg(feature = "aes")]
const AES192_KEY_LEN: usize = 24;
#[cfg(feature = "aes")]
const AES256_KEY_LEN: usize = 32;

/// Message Authentication Code Keyring (HMAC & CMAC)
#[derive(Clone, Debug, ZeroizeOnDrop)]
pub struct Mac {
    pub(crate) keyring: Keyring<Material>,
}

impl Mac {
    /// Opens a [`Mac`] keyring from the given `data` and validates the
    /// authenticity with `aad` by means of the [`Envelope`].
    ///
    /// # Errors
    /// Errors if the keyring could not be opened by the or the authenticity
    /// could not be verified by the [`Envelope`] using futures.
    ///
    /// # Example
    /// ```rust
    /// use navajo::Aad;
    /// use navajo::mac::{ Mac, Algorithm };
    /// use navajo::envelope::InMemory;
    ///
    /// #[tokio::main]
    /// async fn main() {
    ///     let mac = Mac::new(Algorithm::Sha256, None);
    ///     let primary_key = mac.primary_key();
    ///     // in a real application, you would use a real key management service.
    ///     // InMemory is only suitable for testing.
    ///     let in_mem = InMemory::default();
    ///     let data = Mac::seal(Aad::empty(), &mac, &in_mem).await.unwrap();
    ///     let mac = Mac::open(Aad::empty(), data, &in_mem).await.unwrap();
    ///     assert_eq!(mac.primary_key(), primary_key);
    /// }
    /// ```
    pub async fn open<A, D, E>(aad: Aad<A>, data: D, envelope: &E) -> Result<Self, OpenError>
    where
        E: 'static + Envelope,
        D: 'static + AsRef<[u8]> + Send + Sync,
        A: 'static + AsRef<[u8]> + Send + Sync,
    {
        let primitive = Primitive::open(aad, data, envelope).await?;
        if let Some(mac) = primitive.mac() {
            Ok(mac)
        } else {
            Err(OpenError("primitive is not a mac".into()))
        }
    }

    /// Opens a [`Mac`] keyring from the given `data` and validates the
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
    /// use navajo::mac::{ Mac, Algorithm };
    /// use navajo::envelope::InMemory;
    ///
    /// let mac = Mac::new(Algorithm::Sha256, None);
    /// let primary_key = mac.primary_key();
    /// // in a real application, you would use a real key management service.
    /// // InMemory is only suitable for testing.
    /// let in_mem = InMemory::default();
    /// let data = Mac::seal_sync(Aad(&b"associated data"), &mac, &in_mem).unwrap();
    /// let mac = Mac::open_sync(Aad(&b"associated data"), &data, &in_mem).unwrap();
    /// assert_eq!(mac.primary_key(), primary_key);
    /// ```
    pub fn open_sync<A, E, C>(aad: Aad<A>, ciphertext: C, envelope: &E) -> Result<Self, OpenError>
    where
        A: AsRef<[u8]>,
        C: AsRef<[u8]>,
        E: 'static + crate::envelope::sync::Envelope,
    {
        let primitive = Primitive::open_sync(aad, ciphertext, envelope)?;
        if let Some(mac) = primitive.mac() {
            Ok(mac)
        } else {
            Err(OpenError("primitive is not a mac".into()))
        }
    }
    /// Seals a [`Mac`] keyring and tags it with `aad` for future
    /// authenticationby means of the [`Envelope`].
    ///
    /// # Errors
    /// Errors if the keyring could not be sealed by the [`Envelope`].
    ///
    /// # Example
    /// ```rust
    /// use navajo::Aad;
    /// use navajo::mac::{ Mac, Algorithm };
    /// use navajo::envelope::InMemory;
    ///
    /// #[tokio::main]
    /// async fn main() {
    ///     let mac = Mac::new(Algorithm::Sha256, None);
    ///     let primary_key = mac.primary_key();
    ///     // in a real application, you would use a real key management service.
    ///     // InMemory is only suitable for testing.
    ///     let in_mem = InMemory::default();
    ///     let data = Mac::seal(Aad::empty(), &mac, &in_mem).await.unwrap();
    ///     let mac = Mac::open(Aad::empty(), data, &in_mem).await.unwrap();
    ///     assert_eq!(mac.primary_key(), primary_key);
    /// }
    /// ```
    pub async fn seal<A, E>(aad: Aad<A>, mac: &Self, envelope: &E) -> Result<Vec<u8>, SealError>
    where
        A: 'static + AsRef<[u8]> + Send + Sync,
        E: Envelope + 'static,
    {
        Primitive::Mac(mac.clone()).seal(aad, envelope).await
    }
    /// Seals a [`Mac`] keyring and tags it with `aad` for future
    /// authenticationby means of the [`Envelope`].
    ///
    /// # Errors
    /// Errors if the keyring could not be sealed by the [`Envelope`].
    ///
    /// # Example
    /// ```rust
    /// use navajo::Aad;
    /// use navajo::mac::{ Mac, Algorithm };
    /// use navajo::envelope::InMemory;
    ///
    /// let mac = Mac::new(Algorithm::Sha256, None);
    /// let primary_key = mac.primary_key();
    /// // in a real application, you would use a real key management service.
    /// // InMemory is only suitable for testing.
    /// let in_mem = InMemory::default();
    /// let ciphertext = Mac::seal_sync(Aad::empty(), &mac, &in_mem).unwrap();
    /// let mac = Mac::open_sync(Aad::empty(), ciphertext, &in_mem).unwrap();
    /// assert_eq!(mac.primary_key(), primary_key);
    /// ```
    pub fn seal_sync<A, E>(aad: Aad<A>, mac: &Self, envelope: &E) -> Result<Vec<u8>, SealError>
    where
        A: AsRef<[u8]>,
        E: 'static + crate::envelope::sync::Envelope,
    {
        Primitive::Mac(mac.clone()).seal_sync(aad, envelope)
    }

    /// Create a new MAC keyring by generating a key for the given [`Algorithm`]
    /// as the primary.
    pub fn new(algorithm: Algorithm, meta: Option<Metadata>) -> Self {
        Self::generate(&SystemRng, algorithm, meta)
    }

    #[cfg(test)]
    pub fn new_with_rng<N>(rng: &N, algorithm: Algorithm, metadata: Option<Metadata>) -> Self
    where
        N: Rng,
    {
        Self::generate(rng, algorithm, metadata)
    }

    fn generate<N>(rng: &N, algorithm: Algorithm, metadata: Option<Metadata>) -> Self
    where
        N: Rng,
    {
        let bytes = algorithm.generate_key(rng);
        // safe, the key is generated
        let material = Material::new(&bytes, None, algorithm).unwrap();
        let metadata = metadata.map(Arc::new);
        let key = Key::new(
            rng.u32().unwrap(),
            Status::Primary,
            Origin::Navajo,
            material,
            metadata,
        );
        Self {
            keyring: Keyring::new(key),
        }
    }
    /// Create a new MAC keyring by initializing it with the given key data as
    /// primary.
    ///
    /// # Example
    ///
    /// ```rust
    /// use navajo::mac::{Mac, Algorithm};
    /// use hex::{decode, encode};
    /// let external_key = decode("85bcda2d6d76b547e47d8e6ca49b95ff19ea5d8b4e37569b72367d5aa0336d22")
    ///     .unwrap();    
    /// let mac = Mac::new_external_key(&external_key, Algorithm::Sha256, None, None).unwrap();
    /// let tag = mac.compute(b"hello world").omit_header().unwrap();
    ///
    /// assert_eq!(encode(tag), "d8efa1da7b16626d2c193874314bc0a4a67e4f4a77c86a755947c8f82f55a82a");
    /// ```
    pub fn new_external_key<K>(
        key: K,
        algorithm: Algorithm,
        prefix: Option<&[u8]>,
        metadata: Option<Metadata>,
    ) -> Result<Self, KeyError>
    where
        K: AsRef<[u8]>,
    {
        Self::import_key(&SystemRng, key, algorithm, prefix, metadata)
    }
    #[cfg(test)]
    pub fn new_external_key_with_rng<K, N>(
        rng: &N,
        key: K,
        algorithm: Algorithm,
        prefix: Option<&[u8]>,
        metadata: Option<Metadata>,
    ) -> Result<Self, KeyError>
    where
        K: AsRef<[u8]>,
        N: Rng,
    {
        Self::import_key(rng, key, algorithm, prefix, metadata)
    }

    fn import_key<K, N>(
        rng: &N,
        key: K,
        algorithm: Algorithm,
        prefix: Option<&[u8]>,
        metadata: Option<Metadata>,
    ) -> Result<Self, KeyError>
    where
        K: AsRef<[u8]>,
        N: Rng,
    {
        let material = Material::new(key.as_ref(), prefix, algorithm)?;
        let metadata = metadata.map(Arc::new);
        let key = Key::new(
            rng.u32().unwrap(),
            Status::Primary,
            Origin::External,
            material,
            metadata,
        );
        Ok(Self {
            keyring: Keyring::new(key),
        })
    }

    /// Computes a MAC for the given data using the primary key.
    /// # Example
    /// ```rust
    /// use navajo::mac::{Mac, Algorithm};
    /// use hex::{decode, encode};
    /// let external_key = decode("85bcda2d6d76b547e47d8e6ca49b95ff19ea5d8b4e37569b72367d5aa0336d22")
    ///     .unwrap();    
    /// let mac = Mac::new_external_key(&external_key, Algorithm::Sha256, None, None).unwrap();
    /// let tag = mac.compute(b"hello world").omit_header().unwrap();
    ///
    /// assert_eq!(encode(tag), "d8efa1da7b16626d2c193874314bc0a4a67e4f4a77c86a755947c8f82f55a82a");
    /// ```
    pub fn compute(&self, data: &[u8]) -> Tag {
        let mut compute = Computer::new(self);
        compute.update(data);
        compute.finalize()
    }

    /// Computes a [`Tag`] from a [`Stream`] of [`AsRef<[u8]>`](core::convert::AsRef<[u8]>).
    ///
    /// # Examples
    /// ```rust
    /// use navajo::mac::{Mac, Algorithm};
    /// use futures::{ StreamExt, stream };
    ///
    /// #[tokio::main]
    /// async fn main() {
    ///     let mac = Mac::new(Algorithm::Sha256, None);
    ///     let data = vec![b"hello", b"world"];
    ///     let stream = stream::iter(data);
    ///     let tag = mac.compute_stream(stream).await;
    /// }
    /// ```
    pub fn compute_stream<S>(&self, stream: S) -> ComputeStream<S>
    where
        S: Stream,
        S::Item: AsRef<[u8]>,
    {
        let compute = Computer::new(self);
        ComputeStream::new(stream, compute)
    }
    /// Computes a [`Tag`] from a [`TryStream`] of [`AsRef<[u8]>`](core::convert::AsRef<[u8]>).
    ///
    /// # Examples
    /// ```rust
    /// use navajo::mac::{Mac, Algorithm};
    /// use futures::{ TryStream, StreamExt, stream };
    /// fn to_try_stream<T>(d: T) -> Result<T, ()> { Ok(d) }
    ///
    /// #[tokio::main]
    /// async fn main() {
    ///     let mac = Mac::new(Algorithm::Sha256, None);
    ///     let data = vec![b"hello", b"world"];
    ///     let try_stream = stream::iter(data).map(to_try_stream);
    ///     let tag = mac.compute_try_stream(try_stream).await.unwrap();
    ///     // println!("tag: {}", hex::encode(&tag));
    /// }
    /// ```
    pub fn compute_try_stream<S>(&self, try_stream: S) -> ComputeTryStream<S>
    where
        S: TryStream,
        S::Ok: AsRef<[u8]>,
        S::Error: Send + Sync,
    {
        let compute = Computer::new(self);
        ComputeTryStream::new(try_stream, compute)
    }

    /// Compute [`Tag`] from an [`std::io::Read`].
    /// # Examples
    /// ```rust
    /// use navajo::mac::{Mac, Algorithm};
    /// use std::io::Cursor;
    ///
    /// let mac = Mac::new(Algorithm::Sha256, None);
    /// let data = b"hello world";
    /// let tag = mac.compute_reader(&mut Cursor::new(data)).unwrap();
    /// // println!("tag: {}", hex::encode(&tag));
    /// ```
    #[cfg(feature = "std")]
    pub fn compute_reader<N: ?Sized>(&self, reader: &mut N) -> Result<Tag, std::io::Error>
    where
        N: std::io::Read,
    {
        let mut compute = Computer::new(self);
        std::io::copy(reader, &mut compute)?;
        Ok(compute.finalize())
    }
    /// Verifies a [`Tag`] for the given data using the primary key.
    /// # Example
    /// ```rust
    /// use navajo::mac::{Mac, Algorithm};
    /// use hex::{decode, encode};
    /// let external_key = decode("85bcda2d6d76b547e47d8e6ca49b95ff19ea5d8b4e37569b72367d5aa0336d22")
    ///     .unwrap();    
    /// let mac = Mac::new_external_key(&external_key, Algorithm::Sha256, None, None).unwrap();
    /// let tag = mac.compute(b"hello world").omit_header().unwrap();
    /// assert_eq!(encode(&tag), "d8efa1da7b16626d2c193874314bc0a4a67e4f4a77c86a755947c8f82f55a82a");
    /// assert!(mac.verify(tag, b"hello world").is_ok());
    ///
    /// ```
    pub fn verify<T>(&self, tag: T, data: &[u8]) -> Result<Tag, MacVerificationError>
    where
        T: AsRef<Tag>,
    {
        let mut verify = Verifier::new(tag, self);
        verify.update(data);
        verify.finalize()
    }

    /// Verifies a [`Tag`] for the given [`Read`] `reader` using the primary key.
    /// # Example
    /// ```rust
    /// use navajo::mac::{Mac, Algorithm};
    /// use hex::{decode, encode};
    /// use std::io::Cursor;
    ///
    /// let external_key = decode("85bcda2d6d76b547e47d8e6ca49b95ff19ea5d8b4e37569b72367d5aa0336d22")
    ///     .unwrap();    
    /// let mac = Mac::new_external_key(&external_key, Algorithm::Sha256, None, None).unwrap();
    /// let tag = mac.compute(b"hello world").omit_header().unwrap();
    /// assert_eq!(encode(&tag), "d8efa1da7b16626d2c193874314bc0a4a67e4f4a77c86a755947c8f82f55a82a");
    /// assert!(mac.verify_reader(tag, &mut Cursor::new(b"hello world")).is_ok());
    ///
    /// ```
    ///
    #[cfg(feature = "std")]
    pub fn verify_reader<T, N: ?Sized>(
        &self,
        tag: T,
        reader: &mut N,
    ) -> Result<Tag, crate::error::MacVerificationReadError>
    where
        T: AsRef<Tag>,
        N: std::io::Read,
    {
        let mut verify = Verifier::new(tag, self);
        std::io::copy(reader, &mut verify)?;
        let verified = verify.finalize()?;
        Ok(verified)
    }
    /// Verifies a [`Tag`] against a [`Stream`] `stream` of [`AsRef<[u8]>`](core::convert::AsRef<[u8]>).
    ///
    /// # Examples
    /// ```rust
    /// use navajo::mac::{Mac, Algorithm};
    /// use futures::{ StreamExt, stream };
    /// use hex::{encode, decode};
    ///
    /// #[tokio::main]
    /// async fn main() {
    ///     let external_key = decode("85bcda2d6d76b547e47d8e6ca49b95ff19ea5d8b4e37569b72367d5aa0336d22")
    ///         .unwrap();    
    ///     let mac = Mac::new_external_key(&external_key, Algorithm::Sha256, None, None).unwrap();
    ///     let tag = mac.compute(b"hello world").omit_header().unwrap();
    ///     assert_eq!(encode(&tag), "d8efa1da7b16626d2c193874314bc0a4a67e4f4a77c86a755947c8f82f55a82a");
    ///     let data = vec![&b"hello"[..], &b" "[..], &b"world"[..]];
    ///     let stream = stream::iter(data);
    ///     let tag = mac.verify_stream(tag, stream).await.unwrap();
    ///     // println!("tag: {}", hex::encode(&tag))
    /// }
    /// ```
    pub fn verify_stream<T, S>(&self, tag: T, stream: S) -> VerifyStream<S, T>
    where
        T: AsRef<Tag> + Send + Sync,
        S: Stream,
        S::Item: AsRef<[u8]>,
    {
        let verify = Verifier::new(tag, self);
        VerifyStream::new(stream, verify)
    }
    /// Verifies a [`Tag`] against a [`TryStream`] `stream` of [`AsRef<[u8]>`](core::convert::AsRef<[u8]>).
    ///
    /// # Examples
    /// ```rust
    /// use navajo::mac::{Mac, Algorithm};
    /// use futures::{ StreamExt, stream };
    /// use hex::{decode, encode};
    /// fn to_try_stream<T>(d: T) -> Result<T, ()> { Ok(d) }
    ///
    /// #[tokio::main]
    /// async fn main() {
    ///     let external_key = decode("85bcda2d6d76b547e47d8e6ca49b95ff19ea5d8b4e37569b72367d5aa0336d22")
    ///         .unwrap();    
    ///     let mac = Mac::new_external_key(&external_key, Algorithm::Sha256, None, None).unwrap();
    ///     let tag = mac.compute(b"hello world").omit_header().unwrap();
    ///     assert_eq!(encode(&tag), "d8efa1da7b16626d2c193874314bc0a4a67e4f4a77c86a755947c8f82f55a82a");
    ///     let data = vec![&b"hello"[..], &b" "[..], &b"world"[..]];
    ///     let stream = stream::iter(data).map(to_try_stream);
    ///     
    ///     assert!(mac.verify_try_stream(tag, stream).await.is_ok());
    /// }
    /// ```
    pub fn verify_try_stream<S, T>(&self, tag: T, stream: S) -> VerifyTryStream<S, T>
    where
        T: AsRef<Tag> + Send + Sync,
        S: TryStream,
        S::Ok: AsRef<[u8]>,
        S::Error: Send + Sync,
    {
        let verify = Verifier::new(tag, self);
        VerifyTryStream::new(stream, verify)
    }

    fn generate_key<N>(
        &mut self,
        rng: &N,
        algorithm: Algorithm,
        origin: Origin,
        metadata: Option<Metadata>,
    ) -> MacKeyInfo
    where
        N: Rng,
    {
        let bytes = algorithm.generate_key(rng);
        self.create_key(rng, algorithm, &bytes, None, origin, metadata)
            .unwrap() // safe, the key is generated
    }

    /// Returns [`MacKeyInfo`] for the primary key.
    pub fn primary_key(&self) -> MacKeyInfo {
        self.keyring.primary().into()
    }
    /// Returns a [`Vec`] containing a [`MacKeyInfo`] for each key in this keyring.
    pub fn keys(&self) -> Vec<MacKeyInfo> {
        self.keyring.keys().iter().map(MacKeyInfo::new).collect()
    }

    pub fn add(&mut self, algorithm: Algorithm, metadata: Option<Metadata>) -> MacKeyInfo {
        self.generate_key(&SystemRng, algorithm, Origin::Navajo, metadata)
    }

    #[cfg(test)]
    pub fn add_with_rng<N>(
        &mut self,
        rng: &N,
        algorithm: Algorithm,
        metadata: Option<Metadata>,
    ) -> MacKeyInfo
    where
        N: Rng,
    {
        self.generate_key(rng, algorithm, Origin::Navajo, metadata)
    }

    pub fn add_external<K>(
        &mut self,
        key: K,
        algorithm: Algorithm,
        prefix: Option<&[u8]>,
        metadata: Option<Metadata>,
    ) -> Result<MacKeyInfo, KeyError>
    where
        K: AsRef<[u8]>,
    {
        self.create_key(
            &SystemRng,
            algorithm,
            key.as_ref(),
            prefix,
            Origin::External,
            metadata,
        )
    }

    pub fn add_external_with_rng<N, K>(
        &mut self,
        rng: &N,
        key: K,
        algorithm: Algorithm,
        prefix: Option<&[u8]>,
        metadata: Option<Metadata>,
    ) -> Result<MacKeyInfo, KeyError>
    where
        K: AsRef<[u8]>,
        N: Rng,
    {
        self.create_key(
            rng,
            algorithm,
            key.as_ref(),
            prefix,
            Origin::External,
            metadata,
        )
    }

    pub fn promote(
        &mut self,
        key_id: impl Into<u32>,
    ) -> Result<MacKeyInfo, crate::error::KeyNotFoundError> {
        self.keyring.promote(key_id).map(MacKeyInfo::new)
    }

    pub fn disable(
        &mut self,
        key_id: impl Into<u32>,
    ) -> Result<MacKeyInfo, crate::error::DisableKeyError<Algorithm>> {
        self.keyring.disable(key_id).map(MacKeyInfo::new)
    }

    pub fn enable(&mut self, key_id: impl Into<u32>) -> Result<MacKeyInfo, KeyNotFoundError> {
        self.keyring.enable(key_id).map(MacKeyInfo::new)
    }

    pub fn delete(
        &mut self,
        key_id: impl Into<u32>,
    ) -> Result<MacKeyInfo, RemoveKeyError<Algorithm>> {
        self.keyring.remove(key_id).map(|k| MacKeyInfo::new(&k))
    }

    pub fn update_key_meta(
        &mut self,
        key_id: impl Into<u32>,
        metadata: Option<Metadata>,
    ) -> Result<MacKeyInfo, KeyNotFoundError> {
        self.keyring
            .update_key_metadata(key_id, metadata)
            .map(MacKeyInfo::new)
    }

    pub(crate) fn keyring(&self) -> &Keyring<Material> {
        &self.keyring
    }
    pub(crate) fn from_keyring(keyring: Keyring<Material>) -> Self {
        Self { keyring }
    }

    fn create_key<N>(
        &mut self,
        rng: &N,
        algorithm: Algorithm,
        value: &[u8],
        prefix: Option<&[u8]>,
        origin: Origin,
        metadata: Option<Metadata>,
    ) -> Result<MacKeyInfo, KeyError>
    where
        N: Rng,
    {
        let material = Material::new(value, prefix, algorithm)?;
        let id = self.keyring.next_id(rng);
        let metadata = metadata.map(Arc::new);
        let key = Key::new(id, Status::Secondary, origin, material, metadata);
        let info = MacKeyInfo::new(&key);
        self.keyring.add(key);
        Ok(info)
    }

    pub fn set_key_metadata(
        &mut self,
        key_id: u32,
        metadata: Option<Metadata>,
    ) -> Result<MacKeyInfo, KeyNotFoundError> {
        self.keyring.update_key_metadata(key_id, metadata)?;
        let key = self.keyring.get(key_id)?;
        Ok(MacKeyInfo::new(key))
    }
}

impl AsRef<Mac> for Mac {
    fn as_ref(&self) -> &Self {
        self
    }
}

#[cfg(test)]
mod tests {

    use crate::envelope::InMemory;
    use crate::mac::{Algorithm, Mac};
    use crate::Aad;

    #[test]
    fn test_seal_unseal_sync() {
        let mac = Mac::new(Algorithm::Sha256, None);
        let primary_key = mac.primary_key();
        // in a real application, you would use a real key management service.
        // InMemory is only suitable for testing.
        let in_mem = InMemory::default();
        let ciphertext = Mac::seal_sync(Aad::empty(), &mac, &in_mem).unwrap();
        let mac = Mac::open_sync(Aad::empty(), ciphertext, &in_mem).unwrap();
        assert_eq!(mac.primary_key(), primary_key);
    }

    #[cfg(feature = "std")]
    #[tokio::test]
    async fn test_seal_unseal() {
        let mac = Mac::new(Algorithm::Sha256, None);
        let primary_key = mac.primary_key();
        // in a real application, you would use a real key management service.
        // InMemory is only suitable for testing.
        let in_mem = InMemory::default();

        let data = Mac::seal(Aad::empty(), &mac, &in_mem).await.unwrap();

        let mac = Mac::open(Aad::empty(), data, &in_mem).await.unwrap();
        assert_eq!(mac.primary_key(), primary_key);
    }
}
