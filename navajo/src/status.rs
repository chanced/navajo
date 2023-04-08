use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Status {
    /// Indicates that the key is active and the primary key in the keyring. It
    /// will be used, by default, for encryption.
    ///
    /// The key will be used for decryption when aplicable (i.e. ciphertext
    /// encrypted with it).
    Primary,
    /// Indicates that the key is active and can be used for cryptographic
    /// purposes.
    ///
    /// The key will be used for verification or decryption when applicable
    /// but will not be used for signing or encryption.
    Secondary,
    /// A disabled key is not active and cannot be used for cryptographic purposes.
    ///
    /// While disabled keys are present in the keyring, they are effectively deleted
    /// but remain in a recoverable state.
    Disabled,
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
    /// Returns `true` if the `Status` is `Primary` or `Secondary`.
    pub fn is_enabled(&self) -> bool {
        !self.is_disabled()
    }
    /// Returns `true` if `Disabled`.
    pub fn is_disabled(&self) -> bool {
        matches!(self, Self::Disabled)
    }
}

impl From<Status> for i8 {
    fn from(s: Status) -> Self {
        s as i8
    }
}
