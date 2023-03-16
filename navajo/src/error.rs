use core::array::TryFromSliceError;

use alloc::{
    borrow::Cow,
    fmt::{self, Debug, Display},
    format,
    string::{String, ToString},
};

#[cfg(not(feature = "std"))]
pub trait Error: core::fmt::Debug + core::fmt::Display {}

#[cfg(feature = "std")]
pub use std::error::Error;

#[derive(Debug)]
pub struct RandomError(pub rand_core::Error);

impl RandomError {
    pub fn new(inner: rand_core::Error) -> Self {
        Self(inner)
    }
    pub fn inner(&self) -> &rand_core::Error {
        &self.0
    }
    pub fn take_inner(self) -> rand_core::Error {
        self.0
    }
}

impl Error for RandomError {}

impl core::fmt::Display for RandomError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "navajo: error generating random bytes\n\ncaused by: {}",
            self.0
        )
    }
}

impl From<RandomError> for rand_core::Error {
    fn from(err: RandomError) -> Self {
        err.0
    }
}

impl From<rand_core::Error> for RandomError {
    fn from(err: rand_core::Error) -> Self {
        Self(err)
    }
}

#[derive(Debug, Clone, Copy)]
pub struct KeyNotFoundError(pub u32);

impl Error for KeyNotFoundError {}
impl From<u32> for KeyNotFoundError {
    fn from(key: u32) -> Self {
        Self(key)
    }
}

impl fmt::Display for KeyNotFoundError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "navajo: missing key: {}", self.0)
    }
}

#[derive(Clone, Debug)]
pub struct UnspecifiedError;
impl Error for UnspecifiedError {}

#[cfg(feature = "ring")]
impl From<ring::error::Unspecified> for UnspecifiedError {
    fn from(_: ring::error::Unspecified) -> Self {
        Self
    }
}

impl fmt::Display for UnspecifiedError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "navajo: unspecified error")
    }
}

#[derive(Clone, Debug)]
pub struct SegmentLimitExceededError;
impl core::fmt::Display for SegmentLimitExceededError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "counter limit exceeded")
    }
}
impl Error for SegmentLimitExceededError {}

#[derive(Clone, Debug)]
pub enum EncryptError {
    Unspecified,
    SegmentLimitExceeded,
    EmptyCleartext,
}
impl Error for EncryptError {}

impl fmt::Display for EncryptError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unspecified => fmt::Display::fmt(&UnspecifiedError, f),
            Self::SegmentLimitExceeded => fmt::Display::fmt(&SegmentLimitExceededError, f),
            Self::EmptyCleartext => write!(f, "plaintext is empty"),
        }
    }
}

impl From<aes_gcm::Error> for EncryptError {
    fn from(_: aes_gcm::Error) -> Self {
        Self::Unspecified
    }
}

impl From<SegmentLimitExceededError> for EncryptError {
    fn from(_: SegmentLimitExceededError) -> Self {
        Self::SegmentLimitExceeded
    }
}

#[cfg(feature = "std")]
impl From<EncryptError> for std::io::Error {
    fn from(e: EncryptError) -> Self {
        Self::new(std::io::ErrorKind::Other, e)
    }
}

impl From<UnspecifiedError> for EncryptError {
    fn from(_: UnspecifiedError) -> Self {
        Self::Unspecified
    }
}
#[cfg(feature = "ring")]
impl From<ring::error::Unspecified> for EncryptError {
    fn from(_: ring::error::Unspecified) -> Self {
        Self::Unspecified
    }
}

pub enum EncryptTryStreamError<E> {
    Encrypt(EncryptError),
    Upstream(E),
}
#[cfg(feature = "std")]
impl<E> Error for EncryptTryStreamError<E> where E: std::error::Error {}

impl<E> core::fmt::Debug for EncryptTryStreamError<E>
where
    E: core::fmt::Debug,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Encrypt(e) => write!(f, "EncryptError({e:?})"),
            Self::Upstream(e) => write!(f, "Upstream({e:?})"),
        }
    }
}
impl<E> From<EncryptError> for EncryptTryStreamError<E> {
    fn from(e: EncryptError) -> Self {
        Self::Encrypt(e)
    }
}
impl<E> core::fmt::Display for EncryptTryStreamError<E>
where
    E: core::fmt::Display,
{
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Encrypt(e) => core::fmt::Display::fmt(e, f),
            Self::Upstream(e) => core::fmt::Display::fmt(e, f),
        }
    }
}

#[derive(Debug, Clone)]
pub enum DecryptError {
    /// The underlying cryptography library, *ring* returned an unspecified error.
    Unspecified,
    /// The keyset does not contain the key used to encrypt the ciphertext
    KeyNotFound(KeyNotFoundError),
    SegmentLimitExceeded,
    EmptyCiphertext,
}

impl Error for DecryptError {}

impl From<KeyNotFoundError> for DecryptError {
    fn from(e: KeyNotFoundError) -> Self {
        Self::KeyNotFound(e)
    }
}
impl From<SegmentLimitExceededError> for DecryptError {
    fn from(_: SegmentLimitExceededError) -> Self {
        Self::SegmentLimitExceeded
    }
}
#[cfg(feature = "std")]
impl From<DecryptError> for std::io::Error {
    fn from(e: DecryptError) -> Self {
        Self::new(std::io::ErrorKind::Other, e)
    }
}

impl From<MalformedError> for DecryptError {
    fn from(_: MalformedError) -> Self {
        Self::Unspecified
    }
}

impl From<rust_crypto_aead::Error> for DecryptError {
    fn from(_: rust_crypto_aead::Error) -> Self {
        Self::Unspecified
    }
}
impl fmt::Display for DecryptError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unspecified => fmt::Display::fmt(&UnspecifiedError, f),
            Self::KeyNotFound(e) => fmt::Display::fmt(e, f),
            Self::SegmentLimitExceeded => fmt::Display::fmt(&SegmentLimitExceededError, f),
            Self::EmptyCiphertext => write!(f, "navajo: ciphertext must not be empty"),
        }
    }
}

impl From<UnspecifiedError> for DecryptError {
    fn from(_e: UnspecifiedError) -> Self {
        Self::Unspecified
    }
}
#[cfg(feature = "ring")]
impl From<ring::error::Unspecified> for DecryptError {
    fn from(_: ring::error::Unspecified) -> Self {
        Self::Unspecified
    }
}

pub enum DecryptStreamError<E> {
    Decrypt(DecryptError),
    Upstream(E),
}
#[cfg(feature = "std")]
impl<E> Error for DecryptStreamError<E> where E: std::error::Error {}
impl<E> Debug for DecryptStreamError<E>
where
    E: Debug,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Decrypt(e) => write!(f, "DecryptError({e:?})"),
            Self::Upstream(e) => write!(f, "Upstream({e:?})"),
        }
    }
}
impl<E> From<DecryptError> for DecryptStreamError<E> {
    fn from(e: DecryptError) -> Self {
        Self::Decrypt(e)
    }
}
impl<E> core::fmt::Display for DecryptStreamError<E>
where
    E: core::fmt::Display,
{
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Decrypt(e) => core::fmt::Display::fmt(e, f),
            Self::Upstream(e) => core::fmt::Display::fmt(e, f),
        }
    }
}

#[derive(Debug, Clone)]
pub struct MalformedError(pub Cow<'static, str>);
impl Error for MalformedError {}

impl From<&'static str> for MalformedError {
    fn from(s: &'static str) -> Self {
        Self(Cow::Borrowed(s))
    }
}

impl From<String> for MalformedError {
    fn from(s: String) -> Self {
        Self(Cow::Owned(s))
    }
}

impl fmt::Display for MalformedError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "navajo: malformed ciphertext: {}", &self.0)
    }
}

#[derive(Clone, Copy, Debug)]
pub struct InvalidAlgorithm(pub u8);
impl Error for InvalidAlgorithm {}

impl fmt::Display for InvalidAlgorithm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "navajo: invalid algorithm \"{}\"", self.0)
    }
}

impl From<u8> for InvalidAlgorithm {
    fn from(v: u8) -> Self {
        Self(v)
    }
}
#[derive(Debug)]
pub enum TruncationError {
    NotTruncatable(String),
    LengthExceeded,
    MinLengthNotMet,
}
impl Error for TruncationError {}

impl Display for TruncationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotTruncatable(alg) => {
                write!(f, "navajo: truncation not supported for algorithm {alg}")
            }
            Self::LengthExceeded => write!(f, "navajo: truncation length exceeded"),
            Self::MinLengthNotMet => write!(f, "navajo: truncation min length not met"),
        }
    }
}
#[cfg(feature = "std")]
#[derive(Debug)]
pub enum MacVerificationReadError {
    MacVerificationError,
    IoError(std::io::Error),
}
#[cfg(feature = "std")]
impl Error for MacVerificationError {}

#[cfg(feature = "std")]
impl core::fmt::Display for MacVerificationReadError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::MacVerificationError => write!(f, "MAC verification failed"),
            Self::IoError(e) => write!(f, "io error: {e}"),
        }
    }
}
#[cfg(feature = "std")]
impl From<std::io::Error> for MacVerificationReadError {
    fn from(e: std::io::Error) -> Self {
        Self::IoError(e)
    }
}
#[cfg(feature = "std")]
impl From<MacVerificationError> for MacVerificationReadError {
    fn from(_: MacVerificationError) -> Self {
        Self::MacVerificationError
    }
}

#[cfg(feature = "std")]
impl std::error::Error for MacVerificationReadError {}

#[derive(Debug, Clone)]
pub struct MacVerificationError;
impl fmt::Display for MacVerificationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "MAC verification failed")
    }
}

impl From<UnspecifiedError> for MacVerificationError {
    fn from(_: UnspecifiedError) -> Self {
        Self {}
    }
}

#[derive(Debug)]
pub struct SealError(pub String);
impl Error for SealError {}

impl fmt::Display for SealError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "error: failed to seal:\n\ncaused by:\n\t{}", self.0)
    }
}
impl From<String> for SealError {
    fn from(e: String) -> Self {
        Self(e)
    }
}

impl From<&str> for SealError {
    fn from(e: &str) -> Self {
        Self(e.to_string())
    }
}

impl From<serde_json::Error> for SealError {
    fn from(e: serde_json::Error) -> Self {
        Self(e.to_string())
    }
}

impl From<chacha20poly1305::Error> for SealError {
    fn from(e: chacha20poly1305::Error) -> Self {
        Self(e.to_string())
    }
}

#[derive(Debug)]
pub struct OpenError(pub String);
impl Error for OpenError {}

impl fmt::Display for OpenError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "error: failed to open:\n\ncaused by:\n\t{}", self.0)
    }
}

impl From<String> for OpenError {
    fn from(e: String) -> Self {
        Self(e)
    }
}
impl From<&str> for OpenError {
    fn from(e: &str) -> Self {
        Self(e.to_string())
    }
}

impl From<serde_json::Error> for OpenError {
    fn from(e: serde_json::Error) -> Self {
        Self(e.to_string())
    }
}

impl From<chacha20poly1305::Error> for OpenError {
    fn from(_: chacha20poly1305::Error) -> Self {
        Self("error decrypting with chacha20poly1305".to_string())
    }
}
impl From<crypto_common::InvalidLength> for OpenError {
    fn from(e: crypto_common::InvalidLength) -> Self {
        Self(e.to_string())
    }
}

#[cfg(any(
    feature = "aead",
    feature = "daead",
    feature = "mac",
    feature = "signature",
))]
#[derive(Debug, Clone)]
pub enum RemoveKeyError<A> {
    IsPrimaryKey(crate::KeyInfo<A>),
    KeyNotFound(KeyNotFoundError),
}
#[cfg(any(
    feature = "aead",
    feature = "daead",
    feature = "mac",
    feature = "signature",
))]
#[cfg(any(
    feature = "aead",
    feature = "daead",
    feature = "mac",
    feature = "signature",
))]
impl<A> fmt::Display for RemoveKeyError<A> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::IsPrimaryKey(_) => write!(f, "navajo: cannot remove primary key"),
            Self::KeyNotFound(e) => fmt::Display::fmt(e, f),
        }
    }
}
#[cfg(any(
    feature = "aead",
    feature = "daead",
    feature = "mac",
    feature = "signature",
))]
impl<A> From<crate::KeyInfo<A>> for RemoveKeyError<A> {
    fn from(info: crate::KeyInfo<A>) -> Self {
        Self::IsPrimaryKey(info)
    }
}
#[cfg(any(
    feature = "aead",
    feature = "daead",
    feature = "mac",
    feature = "signature",
))]
impl<A> From<KeyNotFoundError> for RemoveKeyError<A> {
    fn from(e: KeyNotFoundError) -> Self {
        Self::KeyNotFound(e)
    }
}

#[cfg(feature = "std")]
impl<A> std::error::Error for RemoveKeyError<A> where A: Debug {}

#[cfg(any(
    feature = "aead",
    feature = "daead",
    feature = "mac",
    feature = "signature",
))]
#[derive(Debug, Clone)]
pub enum DisableKeyError<A> {
    IsPrimaryKey(crate::KeyInfo<A>),
    KeyNotFound(KeyNotFoundError),
}
#[cfg(any(
    feature = "aead",
    feature = "daead",
    feature = "mac",
    feature = "signature",
))]
impl<A> fmt::Display for DisableKeyError<A> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::IsPrimaryKey(_) => write!(f, "cannot Disable primary key"),
            Self::KeyNotFound(e) => fmt::Display::fmt(e, f),
        }
    }
}
#[cfg(any(
    feature = "aead",
    feature = "daead",
    feature = "mac",
    feature = "signature",
))]
impl<A> From<crate::KeyInfo<A>> for DisableKeyError<A> {
    fn from(info: crate::KeyInfo<A>) -> Self {
        Self::IsPrimaryKey(info)
    }
}
#[cfg(any(
    feature = "aead",
    feature = "daead",
    feature = "mac",
    feature = "signature",
))]
impl<A> From<KeyNotFoundError> for DisableKeyError<A> {
    fn from(e: KeyNotFoundError) -> Self {
        Self::KeyNotFound(e)
    }
}

#[cfg(feature = "std")]
impl<A> std::error::Error for DisableKeyError<A> where A: Debug {}

pub enum VerifyStreamError<E> {
    Upstream(E),
    FailedVerification,
}
impl<E> core::fmt::Debug for VerifyStreamError<E>
where
    E: Debug,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Upstream(e) => write!(f, "VerifyStreamError::Upstream({e:?})"),
            Self::FailedVerification => write!(f, "VerifyStreamError::FailedVerification"),
        }
    }
}
impl<E> core::fmt::Display for VerifyStreamError<E>
where
    E: Display,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Upstream(e) => write!(
                f,
                "navajo: failed to verify stream due to upstream error;\n\t{e}"
            ),
            Self::FailedVerification => write!(f, "navajo: failed to verify stream"),
        }
    }
}
#[cfg(feature = "std")]
impl<E> std::error::Error for VerifyStreamError<E> where E: std::error::Error {}

#[cfg(not(feature = "std"))]
impl<E> Error for VerifyStreamError<E> where E: core::fmt::Debug + core::fmt::Display {}

impl<E> From<MacVerificationError> for VerifyStreamError<E> {
    fn from(_: MacVerificationError) -> Self {
        Self::FailedVerification
    }
}

#[derive(Clone, Debug)]
pub struct InvalidLengthError;
impl Error for InvalidLengthError {}

impl Display for InvalidLengthError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "invalid length")
    }
}

#[cfg(feature = "ring")]
impl From<ring::error::Unspecified> for InvalidLengthError {
    fn from(_: ring::error::Unspecified) -> Self {
        Self {}
    }
}

impl From<rust_crypto_hkdf::InvalidLength> for InvalidLengthError {
    fn from(_: rust_crypto_hkdf::InvalidLength) -> Self {
        Self {}
    }
}

pub struct KeyError(pub String);
impl Error for KeyError {}
impl fmt::Display for KeyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "malformed key: {}", self.0)
    }
}
impl fmt::Debug for KeyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "navajo: malformed key: {}", self.0)
    }
}

impl From<String> for KeyError {
    fn from(e: String) -> Self {
        Self(e)
    }
}
impl From<&str> for KeyError {
    fn from(e: &str) -> Self {
        Self(e.to_string())
    }
}
#[cfg(feature = "ring")]
impl From<ring::error::KeyRejected> for KeyError {
    fn from(e: ring::error::KeyRejected) -> Self {
        Self(e.to_string())
    }
}
#[cfg(feature = "p256")]
impl From<pkcs8::Error> for KeyError {
    fn from(e: pkcs8::Error) -> Self {
        Self(e.to_string())
    }
}
impl From<TryFromSliceError> for KeyError {
    fn from(e: TryFromSliceError) -> Self {
        Self(format!("invalid key length: {e}"))
    }
}
impl From<digest::InvalidLength> for KeyError {
    fn from(e: digest::InvalidLength) -> Self {
        Self(format!("invalid key length: {e}"))
    }
}
#[cfg(feature = "ed25519")]
impl From<ed25519_dalek::SignatureError> for KeyError {
    fn from(e: ed25519_dalek::SignatureError) -> Self {
        Self(e.to_string())
    }
}

pub enum VerificationError {}
