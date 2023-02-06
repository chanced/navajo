use core::fmt;
use std::borrow::Cow;

pub use random::Error as RandError;

#[cfg(feature = "ring")]
use ring_compat::ring;

#[derive(Debug, Clone, Copy)]
pub struct KeyNotFoundError(pub u32);

impl fmt::Display for KeyNotFoundError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "missing key: {}", self.0)
    }
}

impl std::error::Error for KeyNotFoundError {}

#[derive(Clone, Debug)]
pub struct UnspecifiedError;
#[cfg(feature = "ring")]
impl From<ring_compat::ring::error::Unspecified> for UnspecifiedError {
    fn from(_: ring_compat::ring::error::Unspecified) -> Self {
        Self
    }
}

impl fmt::Display for UnspecifiedError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "unspecified error")
    }
}

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
impl std::error::Error for EncryptError {}
impl From<UnspecifiedError> for EncryptError {
    fn from(_: UnspecifiedError) -> Self {
        Self::Unspecified
    }
}

pub(crate) enum NonceSequenceError {
    CounterLimitExceeded,
    UnspecifiedError,
}
impl From<ring::error::Unspecified> for NonceSequenceError {
    fn from(_: ring::error::Unspecified) -> Self {
        Self::UnspecifiedError
    }
}
#[derive(Debug)]
pub enum DecryptStreamError<E> {
    Unspecified,
    KeyNotFound(KeyNotFoundError),
    Malformed(MalformedError),
    Upstream(E),
}

impl<E> fmt::Display for DecryptStreamError<E>
where
    E: std::error::Error,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DecryptStreamError::Unspecified => fmt::Display::fmt(&UnspecifiedError, f),
            DecryptStreamError::KeyNotFound(k) => write!(f, "unknown key: {}", k),
            DecryptStreamError::Malformed(e) => write!(f, "malformed ciphertext: {e}"),
            DecryptStreamError::Upstream(e) => fmt::Display::fmt(e, f),
        }
    }
}
impl<E> std::error::Error for DecryptStreamError<E> where E: std::error::Error {}
impl<E> From<DecryptError> for DecryptStreamError<E>
where
    E: std::error::Error,
{
    fn from(e: DecryptError) -> Self {
        match e {
            DecryptError::Unspecified => Self::Unspecified,
            DecryptError::KeyNotFound(k) => Self::KeyNotFound(k),
            DecryptError::Malformed(e) => Self::Malformed(e),
        }
    }
}
#[derive(Debug)]
pub enum EncryptStreamError<E> {
    Unspecified,
    MissingPrimaryKey,
    CounterLimitExceeded,
    EmptyCleartext,
    Upstream(E),
}

impl<E> From<UnspecifiedError> for DecryptStreamError<E> {
    fn from(_: UnspecifiedError) -> Self {
        Self::Unspecified
    }
}

impl<E> From<NonceSequenceError> for EncryptStreamError<E> {
    fn from(e: NonceSequenceError) -> Self {
        match e {
            NonceSequenceError::CounterLimitExceeded => Self::CounterLimitExceeded,
            NonceSequenceError::UnspecifiedError => Self::Unspecified,
        }
    }
}
impl<E> fmt::Display for EncryptStreamError<E>
where
    E: std::error::Error,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unspecified => fmt::Display::fmt(&UnspecifiedError, f),
            Self::MissingPrimaryKey => write!(f, "missing primary key"),
            Self::Upstream(e) => fmt::Display::fmt(e, f),
            Self::CounterLimitExceeded => write!(f, "counter limit exceeded"),
            Self::EmptyCleartext => write!(f, "cleartext is empty"),
        }
    }
}
impl<E> std::error::Error for EncryptStreamError<E> where E: std::error::Error {}
impl<E> From<UnspecifiedError> for EncryptStreamError<E> {
    fn from(e: UnspecifiedError) -> Self {
        Self::Unspecified
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
impl std::error::Error for DecryptError {}
impl From<UnspecifiedError> for DecryptError {
    fn from(e: UnspecifiedError) -> Self {
        Self::Unspecified
    }
}
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

impl std::error::Error for InvalidAlgorithm {}

impl From<u8> for InvalidAlgorithm {
    fn from(v: u8) -> Self {
        Self(v)
    }
}

pub enum TruncationError {
    NotTruncatable,
    TooShort,
}

pub enum MacError {}
