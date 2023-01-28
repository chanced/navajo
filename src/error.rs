use core::fmt;

pub struct UnspecifiedError;
impl From<ring::error::Unspecified> for UnspecifiedError {
    fn from(_: ring::error::Unspecified) -> Self {
        Self
    }
}
impl fmt::Debug for UnspecifiedError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "navajo::UnspecifiedError")
    }
}

impl fmt::Display for UnspecifiedError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "unspecified error")
    }
}

impl std::error::Error for UnspecifiedError {}

pub enum EncryptError {
    Unspecified(UnspecifiedError),
}

pub enum DecryptError {
    /// The underlying cryptography library, *ring* returned an unspecified error.
    Unspecified(UnspecifiedError),
    /// The keyset does not contain the key used to encrypt the ciphertext
    UnknownKey(u32),
    /// The ciphertext is malformed. See the opaque error message for details.
    Malformed(String),
}

impl fmt::Debug for DecryptError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unspecified(e) => e.fmt(f),
            Self::Malformed(e) => write!(f, "malformed ciphertext: {}", &e),
            Self::UnknownKey(e) => write!(f, "unknown key: {}", &e),
        }
    }
}
impl fmt::Display for DecryptError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unspecified(e) => e.fmt(f),
            Self::Malformed(e) => write!(f, "malformed header: {}", &e),
            Self::UnknownKey(e) => write!(f, "invalid key: {}", &e),
        }
    }
}
impl std::error::Error for DecryptError {}
impl From<UnspecifiedError> for DecryptError {
    fn from(e: UnspecifiedError) -> Self {
        Self::Unspecified(e)
    }
}
impl From<ring::error::Unspecified> for DecryptError {
    fn from(e: ring::error::Unspecified) -> Self {
        Self::Unspecified(e.into())
    }
}
