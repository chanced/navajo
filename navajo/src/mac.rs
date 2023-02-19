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

use crate::error::{
    InvalidKeyLength, KeyNotFoundError, MacVerificationError, OpenError, RemoveKeyError, SealError,
};
use crate::{Keyring, Kms, Origin};
use alloc::vec::Vec;
use context::*;
use material::*;
use output::Output;
use output::{rust_crypto_internal_tag, rust_crypto_internal_tags};

/// Message Authentication Code Keyring (HMAC & CMAC)
pub struct Mac {
    keyring: Keyring<Material>,
}

impl Mac {
    /// Opens a [`Mac`] keyring from the given `data` and validates the
    /// authenticity with `associated_data` by means of the [`Kms`].
    ///
    /// # Errors
    /// Errors if the keyring could not be opened by the or the authenticity
    /// could not be verified by the [`Kms`] using futures.
    ///
    /// # Example
    /// ```rust
    /// use navajo::mac::{ Mac, Algorithm };
    /// use navajo::kms::InMemory;
    ///
    /// #[tokio::main]
    /// async fn main() {
    ///     let mac = Mac::new(Algorithm::Sha256, None);
    ///     let primary_key = mac.primary_key();
    ///     // in a real application, you would use a real key management service.
    ///     // InMemory is only suitable for testing.
    ///     let kms = InMemory::default();
    ///     let data = Mac::seal(&mac, &[], &kms).await.unwrap();
    ///     let mac = Mac::open(&data, &[], &kms).await.unwrap();
    ///     assert_eq!(mac.primary_key(), primary_key);
    /// }
    /// ```
    pub async fn open<K>(data: &[u8], associated_data: &[u8], kms: K) -> Result<Self, OpenError>
    where
        K: Kms,
    {
        let keyring = Keyring::<Material>::open(data, associated_data, kms).await?;
        Ok(Self { keyring })
    }

    /// Opens a [`Mac`] keyring from the given `data` and validates the
    /// authenticity with `associated_data` by means of the [`Kms`] using
    /// blocking APIs.
    ///
    /// # Errors
    /// Errors if the keyring could not be opened by the or the authenticity
    /// could not be verified by the [`Kms`].
    ///
    /// # Example
    /// ```rust
    /// use navajo::mac::{ Mac, Algorithm };
    /// use navajo::kms::InMemory;
    ///
    /// let mac = Mac::new(Algorithm::Sha256, None);
    /// let primary_key = mac.primary_key();
    /// // in a real application, you would use a real key management service.
    /// // InMemory is only suitable for testing.
    /// let kms = InMemory::default();
    /// let data = Mac::seal_sync(&mac, &[], &kms).unwrap();
    /// let mac = Mac::open_sync(&data, &[], &kms).unwrap();
    /// assert_eq!(mac.primary_key(), primary_key);
    /// ```
    pub fn open_sync<K>(data: &[u8], associated_data: &[u8], kms: K) -> Result<Self, OpenError>
    where
        K: Kms,
    {
        let keyring = Keyring::<Material>::open_sync(data, associated_data, kms)?;
        Ok(Self { keyring })
    }
    /// Seals a [`Mac`] keyring and tags it with `associated_data` for future
    /// authenticationby means of the [`Kms`].
    ///
    /// # Errors
    /// Errors if the keyring could not be sealed by the [`Kms`].
    ///
    /// # Example
    /// ```rust
    /// use navajo::mac::{ Mac, Algorithm };
    /// use navajo::kms::InMemory;
    ///
    /// #[tokio::main]
    /// async fn main() {
    ///     let mac = Mac::new(Algorithm::Sha256, None);
    ///     let primary_key = mac.primary_key();
    ///     // in a real application, you would use a real key management service.
    ///     // InMemory is only suitable for testing.
    ///     let kms = InMemory::default();
    ///     let data = Mac::seal(&mac, &[], &kms).await.unwrap();
    ///     let mac = Mac::open(&data, &[], &kms).await.unwrap();
    ///     assert_eq!(mac.primary_key(), primary_key);
    /// }
    /// ```
    pub async fn seal<K>(mac: &Self, associated_data: &[u8], kms: K) -> Result<Vec<u8>, SealError>
    where
        K: Kms,
    {
        Keyring::seal(mac.keyring(), associated_data, kms).await
    }
    /// Seals a [`Mac`] keyring and tags it with `associated_data` for future
    /// authenticationby means of the [`Kms`].
    ///
    /// # Errors
    /// Errors if the keyring could not be sealed by the [`Kms`].
    ///
    /// # Example
    /// ```rust
    /// use navajo::mac::{ Mac, Algorithm };
    /// use navajo::kms::InMemory;
    ///
    /// let mac = Mac::new(Algorithm::Sha256, None);
    /// let primary_key = mac.primary_key();
    /// // in a real application, you would use a real key management service.
    /// // InMemory is only suitable for testing.
    /// let kms = InMemory::default();
    /// let data = Mac::seal_sync(&mac, &[], &kms).unwrap();
    /// let mac = Mac::open_sync(&data, &[], &kms).unwrap();
    /// assert_eq!(mac.primary_key(), primary_key);
    /// ```
    pub fn seal_sync<K>(mac: &Self, associated_data: &[u8], kms: K) -> Result<Vec<u8>, SealError>
    where
        K: Kms,
    {
        Keyring::seal_sync(mac.keyring(), associated_data, kms)
    }

    /// Create a new MAC keyring by generating a key for the given [`Algorithm`]
    /// as the primary.
    pub fn new(algorithm: Algorithm, meta: Option<serde_json::value::Value>) -> Self {
        let bytes = algorithm.generate_key();
        // safe, the key is generated
        let material = Material::new(&bytes, None, algorithm).unwrap();

        Self {
            keyring: Keyring::new(material, Origin::Generated, meta),
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
    pub fn new_with_external_key(
        key: &[u8],
        algorithm: Algorithm,
        prefix: Option<&[u8]>,
        meta: Option<serde_json::Value>,
    ) -> Result<Self, InvalidKeyLength> {
        // safe, the key is generated
        let material = Material::new(key, prefix, algorithm)?;
        Ok(Self {
            keyring: Keyring::new(material, Origin::Generated, meta),
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

    pub fn add_generated_key(
        &mut self,
        algorithm: Algorithm,
        meta: Option<serde_json::Value>,
    ) -> Result<MacKeyInfo, InvalidKeyLength> {
        let bytes = algorithm.generate_key();
        self.create_key(algorithm, &bytes, None, Origin::Generated, meta)
    }
    pub fn add_external_key(
        &mut self,
        key: &[u8],
        algorithm: Algorithm,
        prefix: Option<&[u8]>,
        meta: Option<serde_json::Value>,
    ) -> Result<MacKeyInfo, InvalidKeyLength> {
        self.create_key(algorithm, key, prefix, Origin::External, meta)
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

    fn keyring(&self) -> &Keyring<Material> {
        &self.keyring
    }

    fn create_key(
        &mut self,
        algorithm: Algorithm,
        bytes: &[u8],
        prefix: Option<&[u8]>,
        origin: Origin,
        meta: Option<serde_json::Value>,
    ) -> Result<MacKeyInfo, InvalidKeyLength> {
        let material = Material::new(bytes, prefix, algorithm)?;
        Ok(MacKeyInfo::new(self.keyring.add(material, origin, meta)))
    }
}

impl AsRef<Mac> for Mac {
    fn as_ref(&self) -> &Self {
        self
    }
}

macro_rules! rust_crypto_internals {
    ($input:tt) => {
        rust_crypto_internal_tags!($input);
        rust_crypto_contexts!($input);
        rust_crypto_keys!($input);
    };
}
rust_crypto_internals!({
    hmac: {
        ring: [Sha256, Sha384, Sha512],
        sha2: [Sha224, Sha512_224, Sha512_256],
        sha3: [Sha3_224, Sha3_256, Sha3_384, Sha3_512],
    },
    cmac: {
        aes: [Aes128, Aes192, Aes256]
    }
});
