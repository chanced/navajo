use core::fmt::{self, Debug, Display};

use alloc::{
    borrow::Cow,
    string::{String, ToString},
};
pub use random::Error as RandError;

#[cfg(feature = "ring")]
use ring;

use crate::KeyInfo;

#[derive(Debug, Clone, Copy)]
pub struct KeyNotFoundError(pub u32);

impl fmt::Display for KeyNotFoundError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "missing key: {}", self.0)
    }
}
#[cfg(feature = "std")]
impl std::error::Error for KeyNotFoundError {}

#[derive(Clone, Debug)]
pub struct UnspecifiedError;
#[cfg(feature = "ring")]
impl From<ring::error::Unspecified> for UnspecifiedError {
    fn from(_: ring::error::Unspecified) -> Self {
        Self
    }
}

impl fmt::Display for UnspecifiedError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "unspecified error")
    }
}

#[cfg(feature = "std")]
impl std::error::Error for UnspecifiedError {}

#[derive(Clone, Debug)]
pub enum EncryptError {
    Unspecified,
    MissingPrimaryKey,
}

impl fmt::Display for EncryptError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unspecified => fmt::Display::fmt(&UnspecifiedError, f),
            Self::MissingPrimaryKey => write!(f, "missing primary key"),
        }
    }
}

impl From<rust_crypto_aead::Error> for EncryptError {
    fn from(_: rust_crypto_aead::Error) -> Self {
        Self::Unspecified
    }
}

#[cfg(feature = "std")]
impl std::error::Error for EncryptError {}

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

#[derive(Clone, Debug)]
pub struct SegmentLimitExceeded;
impl core::fmt::Display for SegmentLimitExceeded {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "counter limit exceeded")
    }
}
#[cfg(feature = "std")]
impl std::error::Error for SegmentLimitExceeded {}

#[derive(Debug)]
pub enum DecryptStreamError<E> {
    Unspecified,
    KeyNotFound(KeyNotFoundError),
    Malformed(MalformedError),
    Upstream(E),
}

impl<E> fmt::Display for DecryptStreamError<E>
where
    E: fmt::Display,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DecryptStreamError::Unspecified => fmt::Display::fmt(&UnspecifiedError, f),
            DecryptStreamError::KeyNotFound(k) => write!(f, "unknown key: {k}"),
            DecryptStreamError::Malformed(e) => write!(f, "malformed ciphertext: {e}"),
            DecryptStreamError::Upstream(e) => fmt::Display::fmt(e, f),
        }
    }
}
#[cfg(feature = "std")]
impl<E> std::error::Error for DecryptStreamError<E> where E: std::error::Error {}
impl<E> From<DecryptError> for DecryptStreamError<E>
where
    E: Debug,
{
    fn from(e: DecryptError) -> Self {
        match e {
            DecryptError::Unspecified => Self::Unspecified,
            DecryptError::KeyNotFound(k) => Self::KeyNotFound(k),
            DecryptError::Malformed(e) => Self::Malformed(e),
        }
    }
}

impl From<rust_crypto_aead::Error> for DecryptError {
    fn from(_: rust_crypto_aead::Error) -> Self {
        Self::Unspecified
    }
}

#[derive(Debug)]
pub enum EncryptStreamError<E> {
    Upstream(E),
    Streaming(StreamingEncryptError),
}
impl<E> From<StreamingEncryptError> for EncryptStreamError<E> {
    fn from(e: StreamingEncryptError) -> Self {
        Self::Streaming(e)
    }
}

#[derive(Debug)]
pub enum StreamingEncryptError {
    Unspecified,
    SegmentLimitExceeded,
    EmptyCleartext,
}
impl From<UnspecifiedError> for StreamingEncryptError {
    fn from(_: UnspecifiedError) -> Self {
        Self::Unspecified
    }
}
impl From<SegmentLimitExceeded> for StreamingEncryptError {
    fn from(_: SegmentLimitExceeded) -> Self {
        Self::SegmentLimitExceeded
    }
}

impl<E> From<UnspecifiedError> for DecryptStreamError<E> {
    fn from(_: UnspecifiedError) -> Self {
        Self::Unspecified
    }
}

impl<E> From<SegmentLimitExceeded> for EncryptStreamError<E> {
    fn from(_: SegmentLimitExceeded) -> Self {
        Self::Streaming(StreamingEncryptError::SegmentLimitExceeded)
    }
}

#[derive(Debug, Clone)]
pub enum DecryptError {
    /// The underlying cryptography library, *ring* returned an unspecified error.
    Unspecified,
    /// The keyset does not contain the key used to encrypt the ciphertext
    KeyNotFound(KeyNotFoundError),
    /// The ciphertext is malformed. See the opaque error message for details.
    Malformed(MalformedError),
}

impl From<KeyNotFoundError> for DecryptError {
    fn from(e: KeyNotFoundError) -> Self {
        Self::KeyNotFound(e)
    }
}

impl fmt::Display for DecryptError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unspecified => fmt::Display::fmt(&UnspecifiedError, f),
            Self::Malformed(e) => fmt::Display::fmt(e, f),
            Self::KeyNotFound(e) => fmt::Display::fmt(e, f),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for DecryptError {}
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

#[derive(Debug, Clone)]
pub struct MalformedError(Cow<'static, str>);

impl<E> From<MalformedError> for DecryptStreamError<E> {
    fn from(e: MalformedError) -> Self {
        Self::Malformed(e)
    }
}

impl From<MalformedError> for DecryptError {
    fn from(e: MalformedError) -> Self {
        Self::Malformed(e)
    }
}

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
        write!(f, "malformed ciphertext: {}", &self.0)
    }
}

#[cfg(feature = "std")]
impl std::error::Error for MalformedError {}

pub(crate) enum HeaderError {
    Unspecified,
    Malformed(MalformedError),
    KeyNotFound(KeyNotFoundError),
}

#[derive(Clone, Copy, Debug)]
pub struct InvalidAlgorithm(pub(crate) u8);
impl fmt::Display for InvalidAlgorithm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "invalid algorithm: {}", self.0)
    }
}

#[cfg(feature = "std")]
impl std::error::Error for InvalidAlgorithm {}

impl From<u8> for InvalidAlgorithm {
    fn from(v: u8) -> Self {
        Self(v)
    }
}
#[derive(Debug)]
pub enum TruncationError {
    NotTruncatable,
    LengthExceeded,
    MinLengthNotMet,
}

#[cfg(feature = "std")]
#[derive(Debug)]
pub enum MacVerificationReadError {
    MacVerificationError,
    IoError(std::io::Error),
}
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
#[cfg(feature = "std")]
impl std::error::Error for MacVerificationError {}

#[derive(Debug, Clone)]
pub struct InvalidKeyLength;

impl core::fmt::Display for InvalidKeyLength {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "invalid key length")
    }
}

#[cfg(feature = "std")]
impl std::error::Error for InvalidKeyLength {}

impl From<crypto_common::InvalidLength> for InvalidKeyLength {
    fn from(_: crypto_common::InvalidLength) -> Self {
        Self {}
    }
}
#[derive(Debug)]
pub struct SealError(pub String);

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

#[cfg(feature = "std")]
impl std::error::Error for SealError {}

#[derive(Debug)]
pub struct OpenError(pub String);

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
    fn from(e: chacha20poly1305::Error) -> Self {
        Self(e.to_string())
    }
}
impl From<crypto_common::InvalidLength> for OpenError {
    fn from(e: crypto_common::InvalidLength) -> Self {
        Self(e.to_string())
    }
}

#[cfg(feature = "std")]
impl std::error::Error for OpenError {}

#[derive(Debug, Clone)]
pub enum RemoveKeyError<A> {
    IsPrimaryKey(KeyInfo<A>),
    KeyNotFound(KeyNotFoundError),
}

impl<A> fmt::Display for RemoveKeyError<A> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::IsPrimaryKey(_) => write!(f, "cannot remove primary key"),
            Self::KeyNotFound(e) => write!(f, "{e}"),
        }
    }
}
impl<A> From<KeyInfo<A>> for RemoveKeyError<A> {
    fn from(info: KeyInfo<A>) -> Self {
        Self::IsPrimaryKey(info)
    }
}
impl<A> From<KeyNotFoundError> for RemoveKeyError<A> {
    fn from(e: KeyNotFoundError) -> Self {
        Self::KeyNotFound(e)
    }
}

#[cfg(feature = "std")]
impl<A> std::error::Error for RemoveKeyError<A> where A: Debug {}

#[derive(Debug, Clone)]
pub enum DisableKeyError<A> {
    IsPrimaryKey(KeyInfo<A>),
    KeyNotFound(KeyNotFoundError),
}

impl<A> fmt::Display for DisableKeyError<A> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::IsPrimaryKey(_) => write!(f, "cannot Disable primary key"),
            Self::KeyNotFound(e) => write!(f, "{e}"),
        }
    }
}
impl<A> From<KeyInfo<A>> for DisableKeyError<A> {
    fn from(info: KeyInfo<A>) -> Self {
        Self::IsPrimaryKey(info)
    }
}
impl<A> From<KeyNotFoundError> for DisableKeyError<A> {
    fn from(e: KeyNotFoundError) -> Self {
        Self::KeyNotFound(e)
    }
}

#[cfg(feature = "std")]
impl<A> std::error::Error for DisableKeyError<A> where A: Debug {}

pub enum VerifyTryStreamError<E> {
    Upstream(E),
    FailedVerification,
}
impl<E> From<MacVerificationError> for VerifyTryStreamError<E> {
    fn from(_: MacVerificationError) -> Self {
        Self::FailedVerification
    }
}

#[derive(Clone, Debug)]
pub struct InvalidLengthError;

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
