use serde::Deserialize;
use serde::Serialize;
use serde_repr::Deserialize_repr as DeserializeRepr;
use serde_repr::Serialize_repr as SerializeRepr;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, SerializeRepr, DeserializeRepr)]
#[repr(u8)]
pub enum KeyStatus {
    /// Indicates that the key is active and the primary key in the keyring. It
    /// will be used, by default, for encryption.
    ///
    /// The key will be used for
    /// decryption when aplicable (i.e. ciphertext encrypted with it).
    Primary,
    /// The indicates that the key is active and can be used for encryption if
    /// specified.
    ///
    /// The key will be used for decryption when applicable
    /// (i.e. ciphertext encrypted with it).
    Secondary,
    /// Indicates that the key is disabled and cannot be used for encryption
    /// except for [daead] queries. It can still be used to decrypt applicable
    /// ciphertext.
    Disabled,
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

pub(crate) fn key_id_len() -> usize {
    4
}
