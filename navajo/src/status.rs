use alloc::{format, string::String};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(try_from = "i8", into = "i8")]
#[repr(i8)]
pub enum Status {
    /// Indicates that the key is active and the primary key in the keyring. It
    /// will be used, by default, for encryption.
    ///
    /// The key will be used for decryption when aplicable (i.e. ciphertext
    /// encrypted with it).
    Primary = 0,
    /// The indicates that the key is active and can be used for encryption if
    /// specified.
    ///
    /// The key will be used for decryption when applicable (i.e. ciphertext
    /// encrypted with it).
    Secondary = 1,

    /// Indicates that the key is disabled and cannot be used for encryption
    /// except for [daead] queries. It can still be used to decrypt applicable
    /// ciphertext.
    Disabled = -1,
}

impl Default for Status {
    fn default() -> Self {
        Self::Secondary
    }
}
impl Status {
    /// Returns `true` if `Primary`.
    pub fn is_primary(&self) -> bool {
        *self == Self::Primary
    }
    pub fn is_secondary(&self) -> bool {
        *self == Self::Secondary
    }

    /// Returns `true` if `Disabled`.
    pub fn is_disabled(&self) -> bool {
        matches!(self, Self::Disabled)
    }
}

impl TryFrom<i8> for Status {
    type Error = String;
    fn try_from(i: i8) -> Result<Self, Self::Error> {
        match i {
            0 => Ok(Self::Primary),
            1 => Ok(Self::Secondary),
            -1 => Ok(Self::Disabled),
            _ => Err(format!("invalid key status: {}", i)),
        }
    }
}

impl From<Status> for i8 {
    fn from(s: Status) -> Self {
        s as i8
    }
}
