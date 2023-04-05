use core::{array::TryFromSliceError, time::Duration};

use alloc::{
    boxed::Box,
    fmt::{self, Debug, Display},
    format,
    string::{String, ToString},
};

#[cfg(feature = "std")]
pub use std::error::Error;

#[cfg(not(feature = "std"))]
pub trait Error: Debug + Display {}

#[cfg(not(feature = "std"))]
impl<T> Error for T where T: Display + Debug {}

use crate::jose::{NumericDate, StringOrStrings};

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
#[cfg(feature = "std")]
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
pub struct KeyDisabledError(pub u32);
impl Display for KeyDisabledError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "navajo: key is disabled: {}", self.0)
    }
}

#[derive(Debug, Clone)]
pub enum KeyNotFoundError {
    Key(u32),
    PubId(String),
}
#[cfg(feature = "std")]
impl Error for KeyNotFoundError {}
impl From<u32> for KeyNotFoundError {
    fn from(key: u32) -> Self {
        Self::Key(key)
    }
}
impl KeyNotFoundError {
    fn id_string(&self) -> String {
        match self {
            KeyNotFoundError::Key(id) => id.to_string(),
            KeyNotFoundError::PubId(id) => id.to_string(),
        }
    }
}
impl fmt::Display for KeyNotFoundError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "navajo: missing key: {}", self.id_string())
    }
}

#[derive(Clone, Debug)]
pub struct UnspecifiedError;

#[cfg(feature = "std")]
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

#[cfg(feature = "std")]
impl Error for SegmentLimitExceededError {}
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum EncryptDeterministicError {
    Unspecified,
    EmptyPlaintext,
}

#[cfg(feature = "std")]
impl Error for EncryptDeterministicError {}
impl Display for EncryptDeterministicError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unspecified => fmt::Display::fmt(&UnspecifiedError, f),
            Self::EmptyPlaintext => write!(f, "plaintext is empty"),
        }
    }
}
impl From<UnspecifiedError> for EncryptDeterministicError {
    fn from(_: UnspecifiedError) -> Self {
        Self::Unspecified
    }
}

#[derive(Clone, Debug)]
pub enum EncryptError {
    Unspecified,
    SegmentLimitExceeded,
    EmptyPlaintext,
}

#[cfg(feature = "std")]
impl Error for EncryptError {}

impl fmt::Display for EncryptError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unspecified => fmt::Display::fmt(&UnspecifiedError, f),
            Self::SegmentLimitExceeded => fmt::Display::fmt(&SegmentLimitExceededError, f),
            Self::EmptyPlaintext => write!(f, "plaintext is empty"),
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
    DisabledKey(KeyDisabledError),
}

#[cfg(feature = "std")]
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
            Self::DisabledKey(e) => fmt::Display::fmt(e, f),
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

#[derive(Debug)]
pub struct MalformedError(Box<dyn Error>);

impl From<base64::DecodeError> for MalformedError {
    fn from(e: base64::DecodeError) -> Self {
        Self(Box::new(e))
    }
}
impl From<serde_json::Error> for MalformedError {
    fn from(e: serde_json::Error) -> Self {
        Self(Box::new(e))
    }
}

impl From<&'static str> for MalformedError {
    fn from(s: &'static str) -> Self {
        #[cfg(feature = "std")]
        {
            s.into()
        }
        #[cfg(not(feature = "std"))]
        {
            Self(Box::new(s))
        }
    }
}

impl From<String> for MalformedError {
    fn from(s: String) -> Self {
        #[cfg(feature = "std")]
        {
            s.into()
        }
        #[cfg(not(feature = "std"))]
        {
            Self(Box::new(s))
        }
    }
}

impl fmt::Display for MalformedError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "navajo: malformed data: {}", &self.0)
    }
}

#[derive(Clone, Debug)]
pub struct InvalidAlgorithmError(pub String);

#[cfg(feature = "std")]
impl Error for InvalidAlgorithmError {}

impl fmt::Display for InvalidAlgorithmError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "navajo: invalid or unsupported algorithm: \"{}\"",
            self.0
        )
    }
}

impl From<String> for InvalidAlgorithmError {
    fn from(v: String) -> Self {
        Self(v)
    }
}
impl From<&str> for InvalidAlgorithmError {
    fn from(v: &str) -> Self {
        Self(v.to_string())
    }
}

#[derive(Debug)]
pub enum TruncationError {
    NotTruncatable(String),
    LengthExceeded,
    MinLengthNotMet,
}

#[cfg(feature = "std")]
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

#[cfg(feature = "std")]
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

#[cfg(feature = "std")]
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
impl From<miniz_oxide::inflate::DecompressError> for OpenError {
    fn from(e: miniz_oxide::inflate::DecompressError) -> Self {
        Self(e.to_string())
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

impl From<aes_gcm::Error> for OpenError {
    fn from(_: aes_gcm::Error) -> Self {
        Self("error decrypting keyring".to_string())
    }
}
impl From<crypto_common::InvalidLength> for OpenError {
    fn from(e: crypto_common::InvalidLength) -> Self {
        Self(e.to_string())
    }
}

#[cfg(any(feature = "aead", feature = "daead", feature = "mac", feature = "dsa",))]
#[derive(Debug, Clone)]
pub enum RemoveKeyError<A> {
    IsPrimaryKey(crate::KeyInfo<A>),
    KeyNotFound(KeyNotFoundError),
}
#[cfg(any(feature = "aead", feature = "daead", feature = "mac", feature = "dsa"))]

impl<A> fmt::Display for RemoveKeyError<A> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::IsPrimaryKey(_) => write!(f, "navajo: cannot remove primary key"),
            Self::KeyNotFound(e) => fmt::Display::fmt(e, f),
        }
    }
}
#[cfg(any(feature = "aead", feature = "daead", feature = "mac", feature = "dsa",))]
impl<A> From<crate::KeyInfo<A>> for RemoveKeyError<A> {
    fn from(info: crate::KeyInfo<A>) -> Self {
        Self::IsPrimaryKey(info)
    }
}
#[cfg(any(feature = "aead", feature = "daead", feature = "mac", feature = "dsa",))]
impl<A> From<KeyNotFoundError> for RemoveKeyError<A> {
    fn from(e: KeyNotFoundError) -> Self {
        Self::KeyNotFound(e)
    }
}

#[cfg(any(feature = "aead", feature = "daead", feature = "mac", feature = "dsa"))]
impl<A> std::error::Error for RemoveKeyError<A> where A: Debug {}

#[cfg(any(feature = "aead", feature = "daead", feature = "mac", feature = "dsa",))]
#[derive(Debug, Clone)]
pub enum DisableKeyError<A> {
    IsPrimaryKey(crate::KeyInfo<A>),
    KeyNotFound(KeyNotFoundError),
}
#[cfg(any(feature = "aead", feature = "daead", feature = "mac", feature = "dsa",))]
impl<A> fmt::Display for DisableKeyError<A> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::IsPrimaryKey(_) => write!(f, "cannot Disable primary key"),
            Self::KeyNotFound(e) => fmt::Display::fmt(e, f),
        }
    }
}
#[cfg(any(feature = "aead", feature = "daead", feature = "mac", feature = "dsa",))]
impl<A> From<crate::KeyInfo<A>> for DisableKeyError<A> {
    fn from(info: crate::KeyInfo<A>) -> Self {
        Self::IsPrimaryKey(info)
    }
}
#[cfg(any(feature = "aead", feature = "daead", feature = "mac", feature = "dsa",))]
impl<A> From<KeyNotFoundError> for DisableKeyError<A> {
    fn from(e: KeyNotFoundError) -> Self {
        Self::KeyNotFound(e)
    }
}

#[cfg(any(feature = "aead", feature = "daead", feature = "mac", feature = "dsa",))]
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
#[cfg(feature = "std")]
impl<E> Error for VerifyStreamError<E> where E: core::fmt::Debug + core::fmt::Display {}

impl<E> From<MacVerificationError> for VerifyStreamError<E> {
    fn from(_: MacVerificationError) -> Self {
        Self::FailedVerification
    }
}

#[derive(Clone, Debug)]
pub struct InvalidLengthError;

#[cfg(feature = "std")]
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

#[cfg(feature = "std")]
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
#[cfg(feature = "signature")]
impl From<signature::Error> for SignatureError {
    fn from(e: signature::Error) -> Self {
        Self::Failure(e.to_string())
    }
}

impl From<elliptic_curve::Error> for KeyError {
    fn from(e: elliptic_curve::Error) -> Self {
        Self(e.to_string())
    }
}

impl From<sec1::Error> for KeyError {
    fn from(e: sec1::Error) -> Self {
        Self(e.to_string())
    }
}
#[derive(Debug, Clone)]
pub enum SignatureError {
    KeyNotFound(String),
    Failure(String),
    InvalidLen(usize),
}

#[cfg(feature = "std")]
impl Error for SignatureError {}

impl Display for SignatureError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SignatureError::KeyNotFound(id) => write!(f, "missing key: {id}"),
            SignatureError::Failure(id) => {
                write!(f, "verification failed: {id}")
            }
            SignatureError::InvalidLen(len) => {
                write!(f, "invalid signature len: {len}")
            }
        }
    }
}
#[cfg(feature = "ring")]
impl From<ring::error::Unspecified> for SignatureError {
    fn from(_: ring::error::Unspecified) -> Self {
        Self::Failure("signature verification failed".to_string())
    }
}

#[derive(Debug)]
pub enum TokenError {
    Signature(SignatureError),
    Validation(TokenValidationError),
    Json(serde_json::Error),
    Malformed,
}
impl From<DecodeError> for TokenError {
    fn from(e: DecodeError) -> Self {
        match e {
            DecodeError::Serde(e) => Self::Json(e),
            DecodeError::Base64(_) => Self::Malformed,
            DecodeError::Malformed(_) => Self::Malformed,
        }
    }
}
#[cfg(feature = "std")]
impl Error for TokenError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Signature(e) => Some(e),
            Self::Validation(e) => Some(e),
            Self::Json(e) => Some(e),
            Self::Malformed => None,
        }
    }
}

impl From<serde_json::Error> for TokenError {
    fn from(e: serde_json::Error) -> Self {
        Self::Json(e)
    }
}

impl From<SignatureError> for TokenError {
    fn from(e: SignatureError) -> Self {
        Self::Signature(e)
    }
}
impl From<MalformedError> for TokenError {
    fn from(_: MalformedError) -> Self {
        Self::Malformed
    }
}

impl Display for TokenError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TokenError::Signature(e) => write!(f, "signature error: {e}"),
            TokenError::Validation(e) => write!(f, "validation error: {e}"),
            TokenError::Malformed => write!(f, "malformed jws"),
            TokenError::Json(e) => write!(f, "json error: {e}"),
        }
    }
}

impl From<base64::DecodeError> for TokenError {
    fn from(_: base64::DecodeError) -> Self {
        Self::Malformed
    }
}
impl From<TokenValidationError> for TokenError {
    fn from(e: TokenValidationError) -> Self {
        Self::Validation(e)
    }
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct DuplicatePubIdError(pub String);

impl Display for DuplicatePubIdError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "duplicate pub id: {}", self.0)
    }
}

#[cfg(feature = "std")]
impl Error for DuplicatePubIdError {}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct InvalidCurveError(pub String);

impl Display for InvalidCurveError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "invalid EllipticCurve: {}", self.0)
    }
}

#[cfg(feature = "std")]
impl Error for InvalidCurveError {}

#[derive(Debug)]
pub enum DecodeError {
    Serde(serde_json::Error),
    Base64(base64::DecodeError),
    Malformed(String),
}

impl From<&str> for DecodeError {
    fn from(e: &str) -> Self {
        Self::Malformed(e.to_string())
    }
}
impl Display for DecodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DecodeError::Serde(e) => write!(f, "serde: {e}"),
            DecodeError::Base64(e) => write!(f, "base64: {e}"),
            DecodeError::Malformed(e) => write!(f, "malformed: {e}"),
        }
    }
}

#[cfg(feature = "std")]
impl Error for DecodeError {}
impl From<serde_json::Error> for DecodeError {
    fn from(e: serde_json::Error) -> Self {
        Self::Serde(e)
    }
}
impl From<base64::DecodeError> for DecodeError {
    fn from(e: base64::DecodeError) -> Self {
        Self::Base64(e)
    }
}

#[derive(Debug, Clone)]
pub enum InvalidNumericDateError {
    InvalidTimestamp(i64),
    OutOfRange(u64),
    #[cfg(feature = "std")]
    SystemTime(std::time::SystemTimeError),
}

impl Display for InvalidNumericDateError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            InvalidNumericDateError::InvalidTimestamp(i) => {
                write!(f, "invalid timestamp: {i}")
            }
            InvalidNumericDateError::OutOfRange(u) => {
                write!(f, "timestamp out of range: {u}")
            }
            #[cfg(feature = "std")]
            InvalidNumericDateError::SystemTime(e) => {
                write!(f, "system time error: {e}",)
            }
        }
    }
}
#[cfg(feature = "std")]
impl From<std::time::SystemTimeError> for InvalidNumericDateError {
    fn from(e: std::time::SystemTimeError) -> Self {
        Self::SystemTime(e)
    }
}
impl From<u64> for InvalidNumericDateError {
    fn from(u: u64) -> Self {
        Self::OutOfRange(u)
    }
}
impl From<i64> for InvalidNumericDateError {
    fn from(e: i64) -> Self {
        Self::InvalidTimestamp(e)
    }
}

#[cfg(feature = "std")]
impl Error for InvalidNumericDateError {}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TokenAudienceError {
    pub expected_audience: Option<String>,
    pub actual: Option<StringOrStrings>,
}

impl Display for TokenAudienceError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.expected_audience {
            Some(aud) => write!(f, "audience \"{aud}\" not present"),
            None => write!(f, "error: audience present but not expected"),
        }
    }
}

#[cfg(feature = "std")]
impl Error for TokenAudienceError {}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct TokenExpiredError {
    pub expiration_time: NumericDate,
    pub now: NumericDate,
    pub clock_skew: Duration,
}

impl Display for TokenExpiredError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "token is expired")
    }
}

#[cfg(feature = "std")]
impl Error for TokenExpiredError {}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct TokenIssuerError {
    pub expected_issuer: Option<String>,
    pub actual: Option<String>,
}

#[cfg(feature = "std")]
impl Error for TokenIssuerError {}

impl Display for TokenIssuerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.expected_issuer {
            Some(iss) => match &self.actual {
                Some(actual) => write!(f, "expected issuer \"{iss}\", got \"{actual}\""),
                None => write!(f, "expected issuer \"{iss}\" but not present"),
            },
            None => write!(f, "issuer present but not expected"),
        }
    }
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct TokenNotYetValidError {
    pub not_before: NumericDate,
    pub now: NumericDate,
    pub clock_skew: Duration,
}

impl Display for TokenNotYetValidError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "token is not yet valid")
    }
}

#[cfg(feature = "std")]
impl Error for TokenNotYetValidError {}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct TokenIssuedAtInFutureError {
    pub issued_at: NumericDate,
    pub now: NumericDate,
    pub clock_skew: Duration,
}

#[cfg(feature = "std")]
impl Error for TokenIssuedAtInFutureError {}

impl Display for TokenIssuedAtInFutureError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "token was issued in the future")
    }
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum TokenValidationError {
    Audience(TokenAudienceError),
    Issuer(TokenIssuerError),
    Expired(TokenExpiredError),
    MissingExpiration,
    NotYetValid(TokenNotYetValidError),
    IssuedAtInFuture(TokenIssuedAtInFutureError),
}
impl Display for TokenValidationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TokenValidationError::Audience(err) => core::fmt::Display::fmt(err, f),
            TokenValidationError::MissingExpiration => write!(f, "token is missing an exp claim"),
            TokenValidationError::Expired(err) => core::fmt::Display::fmt(err, f),
            TokenValidationError::NotYetValid(err) => core::fmt::Display::fmt(err, f),
            TokenValidationError::IssuedAtInFuture(err) => core::fmt::Display::fmt(err, f),
            TokenValidationError::Issuer(err) => core::fmt::Display::fmt(err, f),
        }
    }
}

impl From<TokenAudienceError> for TokenValidationError {
    fn from(e: TokenAudienceError) -> Self {
        Self::Audience(e)
    }
}

impl From<TokenIssuerError> for TokenValidationError {
    fn from(e: TokenIssuerError) -> Self {
        Self::Issuer(e)
    }
}

impl From<TokenExpiredError> for TokenValidationError {
    fn from(e: TokenExpiredError) -> Self {
        Self::Expired(e)
    }
}

impl From<TokenNotYetValidError> for TokenValidationError {
    fn from(e: TokenNotYetValidError) -> Self {
        Self::NotYetValid(e)
    }
}

impl From<TokenIssuedAtInFutureError> for TokenValidationError {
    fn from(e: TokenIssuedAtInFutureError) -> Self {
        Self::IssuedAtInFuture(e)
    }
}

#[cfg(feature = "std")]
impl Error for TokenValidationError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            TokenValidationError::Audience(err) => Some(err),
            TokenValidationError::MissingExpiration => None,
            TokenValidationError::Expired(err) => Some(err),
            TokenValidationError::NotYetValid(err) => Some(err),
            TokenValidationError::IssuedAtInFuture(err) => Some(err),
            TokenValidationError::Issuer(err) => Some(err),
        }
    }
}
