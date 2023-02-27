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
use futures::{Stream, TryStream};
pub use key_info::MacKeyInfo;
pub use stream::{ComputeStream, MacStream, VerifyStream};
pub use try_stream::{ComputeTryStream, MacTryStream, VerifyTryStream};

pub use tag::Tag;
pub use verifier::Verifier;
use zeroize::ZeroizeOnDrop;

use crate::error::{
    KeyError, KeyNotFoundError, MacVerificationError, OpenError, RemoveKeyError, SealError,
};
use crate::primitive::Primitive;
use crate::rand::{Random, SystemRandom};
use crate::{Aad, Envelope, Keyring, Origin};
use alloc::vec::Vec;
use context::*;
pub(crate) use material::Material;

use output::Output;

/// Message Authentication Code Keyring (HMAC & CMAC)
#[derive(Clone, Debug, ZeroizeOnDrop)]
pub struct Mac {
    keyring: Keyring<Material>,
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
    ///     let data = Mac::seal(&mac, Aad::empty(), &in_mem).await.unwrap();
    ///     let mac = Mac::open(Aad::empty(), &data, &in_mem).await.unwrap();
    ///     assert_eq!(mac.primary_key(), primary_key);
    /// }
    /// ```
    pub async fn open<A, E>(aad: Aad<A>, data: &[u8], envelope: &E) -> Result<Self, OpenError>
    where
        E: Envelope + 'static,
        A: AsRef<[u8]> + Send + Sync,
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
    /// let data = Mac::seal_sync(&mac, Aad(&b"associated data"), &in_mem).unwrap();
    /// let mac = Mac::open_sync(Aad(&b"associated data"), &data, &in_mem).unwrap();
    /// assert_eq!(mac.primary_key(), primary_key);
    /// ```
    pub fn open_sync<A, E, C>(aad: Aad<A>, ciphertext: C, envelope: &E) -> Result<Self, OpenError>
    where
        A: AsRef<[u8]>,
        C: AsRef<[u8]>,
        E: Envelope + 'static,
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
    ///     let data = Mac::seal(&mac, Aad::empty(), &in_mem).await.unwrap();
    ///     let mac = Mac::open(Aad::empty(), &data, &in_mem).await.unwrap();
    ///     assert_eq!(mac.primary_key(), primary_key);
    /// }
    /// ```
    pub async fn seal<A, E>(mac: &Self, aad: Aad<A>, envelope: &E) -> Result<Vec<u8>, SealError>
    where
        A: AsRef<[u8]> + Send + Sync,
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
    /// let ciphertext = Mac::seal_sync(&mac, Aad::empty(), &in_mem).unwrap();
    /// let mac = Mac::open_sync(Aad::empty(), ciphertext, &in_mem).unwrap();
    /// assert_eq!(mac.primary_key(), primary_key);
    /// ```
    pub fn seal_sync<A, E>(mac: &Self, aad: Aad<A>, envelope: &E) -> Result<Vec<u8>, SealError>
    where
        A: AsRef<[u8]>,
        E: Envelope,
    {
        Keyring::seal_sync(mac.keyring(), aad, envelope)
    }

    /// Create a new MAC keyring by generating a key for the given [`Algorithm`]
    /// as the primary.
    pub fn new(algorithm: Algorithm, meta: Option<serde_json::value::Value>) -> Self {
        Self::generate(SystemRandom, algorithm, meta)
    }

    #[cfg(test)]
    pub fn new_with_rand<R>(
        rand: R,
        algorithm: Algorithm,
        meta: Option<serde_json::value::Value>,
    ) -> Self
    where
        R: Random,
    {
        Self::generate(rand, algorithm, meta)
    }

    fn generate<R>(rand: R, algorithm: Algorithm, meta: Option<serde_json::value::Value>) -> Self
    where
        R: Random,
    {
        let bytes = algorithm.generate_key(rand.clone());
        // safe, the key is generated
        let material = Material::new(&bytes, None, algorithm).unwrap();
        Self {
            keyring: Keyring::new(&rand, material, Origin::Navajo, meta),
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
    /// let mac = Mac::new_with_external_key(&external_key, Algorithm::Sha256, None, None).unwrap();
    /// let tag = mac.compute(b"hello world").omit_header().unwrap();
    ///
    /// assert_eq!(encode(tag), "d8efa1da7b16626d2c193874314bc0a4a67e4f4a77c86a755947c8f82f55a82a");
    /// ```
    pub fn new_external_key<K>(
        key: K,
        algorithm: Algorithm,
        prefix: Option<&[u8]>,
        meta: Option<serde_json::Value>,
    ) -> Result<Self, KeyError>
    where
        K: AsRef<[u8]>,
    {
        Self::import_key(SystemRandom, key, algorithm, prefix, meta)
    }
    #[cfg(test)]
    pub fn new_external_key_with_rand<R, K>(
        rand: R,
        key: K,
        algorithm: Algorithm,
        prefix: Option<&[u8]>,
        meta: Option<serde_json::Value>,
    ) -> Result<Self, KeyError>
    where
        K: AsRef<[u8]>,
        R: Random,
    {
        Self::import_key(rand, key, algorithm, prefix, meta)
    }

    fn import_key<K, R>(
        rand: R,
        key: K,
        algorithm: Algorithm,
        prefix: Option<&[u8]>,
        meta: Option<serde_json::Value>,
    ) -> Result<Self, KeyError>
    where
        K: AsRef<[u8]>,
        R: Random,
    {
        // safe, the key is generated
        let material = Material::new(key.as_ref(), prefix, algorithm)?;
        Ok(Self {
            keyring: Keyring::new(&rand, material, Origin::Navajo, meta),
        })
    }

    /// Computes a MAC for the given data using the primary key.
    /// # Example
    /// ```rust
    /// use navajo::mac::{Mac, Algorithm};
    /// use hex::{decode, encode};
    /// let external_key = decode("85bcda2d6d76b547e47d8e6ca49b95ff19ea5d8b4e37569b72367d5aa0336d22")
    ///     .unwrap();    
    /// let mac = Mac::new_with_external_key(&external_key, Algorithm::Sha256, None, None).unwrap();
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
    ///     println!("tag: {}", hex::encode(&tag))
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
    ///     println!("tag: {}", hex::encode(&tag));
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
    /// println!("tag: {}", hex::encode(&tag));
    /// ```
    #[cfg(feature = "std")]
    pub fn compute_reader<R: ?Sized>(&self, reader: &mut R) -> Result<Tag, std::io::Error>
    where
        R: std::io::Read,
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
    /// let mac = Mac::new_with_external_key(&external_key, Algorithm::Sha256, None, None).unwrap();
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
    /// let mac = Mac::new_with_external_key(&external_key, Algorithm::Sha256, None, None).unwrap();
    /// let tag = mac.compute(b"hello world").omit_header().unwrap();
    /// assert_eq!(encode(&tag), "d8efa1da7b16626d2c193874314bc0a4a67e4f4a77c86a755947c8f82f55a82a");
    /// assert!(mac.verify_reader(tag, &mut Cursor::new(b"hello world")).is_ok());
    ///
    /// ```
    ///
    #[cfg(feature = "std")]
    pub fn verify_reader<T, R: ?Sized>(
        &self,
        tag: T,
        reader: &mut R,
    ) -> Result<Tag, crate::error::MacVerificationReadError>
    where
        T: AsRef<Tag>,
        R: std::io::Read,
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
    ///     let mac = Mac::new_with_external_key(&external_key, Algorithm::Sha256, None, None).unwrap();
    ///     let tag = mac.compute(b"hello world").omit_header().unwrap();
    ///     assert_eq!(encode(&tag), "d8efa1da7b16626d2c193874314bc0a4a67e4f4a77c86a755947c8f82f55a82a");
    ///     let data = vec![&b"hello"[..], &b" "[..], &b"world"[..]];
    ///     let stream = stream::iter(data);
    ///     let tag = mac.verify_stream(tag, stream).await.unwrap();
    ///     println!("tag: {}", hex::encode(&tag))
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
    ///     let mac = Mac::new_with_external_key(&external_key, Algorithm::Sha256, None, None).unwrap();
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

    pub fn add_key(&mut self, algorithm: Algorithm, meta: Option<serde_json::Value>) -> MacKeyInfo {
        self.generate_key(SystemRandom, algorithm, Origin::Navajo, meta)
    }

    #[cfg(test)]
    pub fn add_key_with_rand<R>(
        &mut self,
        rand: R,
        algorithm: Algorithm,
        meta: Option<serde_json::Value>,
    ) -> MacKeyInfo
    where
        R: Random,
    {
        self.generate_key(rand, algorithm, Origin::Navajo, meta)
    }
    fn generate_key<R>(
        &mut self,
        rand: R,
        algorithm: Algorithm,
        origin: Origin,
        meta: Option<serde_json::Value>,
    ) -> MacKeyInfo
    where
        R: Random,
    {
        let rand = SystemRandom::new();
        let bytes = algorithm.generate_key(rand);
        self.create_key(rand, algorithm, &bytes, None, origin, meta)
            .unwrap() // safe, the key is generated
    }

    pub fn add_external_key<K>(
        &mut self,
        key: K,
        algorithm: Algorithm,
        prefix: Option<&[u8]>,
        meta: Option<serde_json::Value>,
    ) -> Result<MacKeyInfo, KeyError>
    where
        K: AsRef<[u8]>,
    {
        self.create_key(
            SystemRandom,
            algorithm,
            key.as_ref(),
            prefix,
            Origin::External,
            meta,
        )
    }

    pub fn add_external_key_with_rand<R, K>(
        &mut self,
        rand: R,
        key: K,
        algorithm: Algorithm,
        prefix: Option<&[u8]>,
        meta: Option<serde_json::Value>,
    ) -> Result<MacKeyInfo, KeyError>
    where
        K: AsRef<[u8]>,
        R: Random,
    {
        self.create_key(
            SystemRandom,
            algorithm,
            key.as_ref(),
            prefix,
            Origin::External,
            meta,
        )
    }

    /// Returns [`MacKeyInfo`] for the primary key.
    pub fn primary_key(&self) -> MacKeyInfo {
        self.keyring.primary().into()
    }
    /// Returns a [`Vec`] containing a [`MacKeyInfo`] for each key in this keyring.
    pub fn keys(&self) -> Vec<MacKeyInfo> {
        self.keyring.keys().iter().map(MacKeyInfo::new).collect()
    }

    pub fn promote_key(
        &mut self,
        key_id: impl Into<u32>,
    ) -> Result<MacKeyInfo, crate::error::KeyNotFoundError> {
        self.keyring.promote(key_id).map(MacKeyInfo::new)
    }

    pub fn disable_key(
        &mut self,
        key_id: impl Into<u32>,
    ) -> Result<MacKeyInfo, crate::error::DisableKeyError<Algorithm>> {
        self.keyring.disable(key_id).map(MacKeyInfo::new)
    }

    pub fn enable_key(&mut self, key_id: impl Into<u32>) -> Result<MacKeyInfo, KeyNotFoundError> {
        self.keyring.enable(key_id).map(MacKeyInfo::new)
    }

    pub fn remove_key(
        &mut self,
        key_id: impl Into<u32>,
    ) -> Result<MacKeyInfo, RemoveKeyError<Algorithm>> {
        self.keyring.remove(key_id).map(|k| MacKeyInfo::new(&k))
    }

    pub fn update_key_meta(
        &mut self,
        key_id: impl Into<u32>,
        meta: Option<serde_json::Value>,
    ) -> Result<MacKeyInfo, KeyNotFoundError> {
        self.keyring.update_meta(key_id, meta).map(MacKeyInfo::new)
    }

    pub(crate) fn keyring(&self) -> &Keyring<Material> {
        &self.keyring
    }
    pub(crate) fn from_keyring(keyring: Keyring<Material>) -> Self {
        Self { keyring }
    }

    fn create_key<R>(
        &mut self,
        rand: R,
        algorithm: Algorithm,
        value: &[u8],
        prefix: Option<&[u8]>,
        origin: Origin,
        meta: Option<serde_json::Value>,
    ) -> Result<MacKeyInfo, KeyError>
    where
        R: Random,
    {
        let material = Material::new(value, prefix, algorithm)?;
        Ok(MacKeyInfo::new(
            self.keyring.add(&rand, material, origin, meta),
        ))
    }
}

impl AsRef<Mac> for Mac {
    fn as_ref(&self) -> &Self {
        self
    }
}
