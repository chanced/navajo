use core::fmt;

use ring::aead::Nonce;

#[derive(Debug, Clone)]
pub struct KeyNotFoundError(pub u32);

impl fmt::Display for KeyNotFoundError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "missing key: {}", self.0)
    }
}

impl std::error::Error for KeyNotFoundError {}

#[derive(Clone, Debug)]
pub struct UnspecifiedError;
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
    UnknownKey(u32),
    Malformed(String),
    Upstream(E),
}
#[derive(Debug)]
pub enum EncryptStreamError<E> {
    Unspecified,
    MissingPrimaryKey,
    CounterLimitExceeded,
    EmptyCleartext,
    Upstream(E),
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
            Self::Unspecified => fmt::Display::fmt(self, f),
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
    UnknownKey(u32),
    /// The ciphertext is malformed. See the opaque error message for details.
    Malformed(String),
}

impl fmt::Display for DecryptError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unspecified => fmt::Display::fmt(self, f),
            Self::Malformed(e) => write!(f, "malformed header: {}", &e),
            Self::UnknownKey(e) => write!(f, "invalid key: {}", &e),
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
