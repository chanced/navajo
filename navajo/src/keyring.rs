use serde::Deserialize;
use serde::Serialize;

pub(crate) const KEY_ID_LEN: usize = 4;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(try_from = "i8", into = "i8")]
#[repr(i8)]
pub enum KeyStatus {
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

impl Default for KeyStatus {
    fn default() -> Self {
        Self::Secondary
    }
}
impl KeyStatus {
    /// Returns `true` if either `Primary` or `Secondary`.
    pub fn is_active(&self) -> bool {
        match self {
            Self::Secondary | Self::Primary => true,
            Self::Disabled => false,
        }
    }
    /// Returns `true` if `Primary`.
    pub fn is_primary(&self) -> bool {
        *self == Self::Primary
    }
    pub fn is_secondary(&self) -> bool {
        *self == Self::Secondary
    }

    /// Returns `true` if `Disabled`.
    pub fn is_disabled(&self) -> bool {
        match self {
            Self::Secondary | Self::Primary => false,
            Self::Disabled => true,
        }
    }
}

impl TryFrom<i8> for KeyStatus {
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

impl From<KeyStatus> for i8 {
    fn from(s: KeyStatus) -> Self {
        s as i8
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
/// Metadata for a particular key.
pub struct KeyInfo<A> {
    pub id: u32,
    pub algorithm: A,
    pub status: KeyStatus,
    pub created_at_timestamp: u64,
    /// The public key, if applicable.
    pub pub_key: Option<Vec<u8>>,
}
