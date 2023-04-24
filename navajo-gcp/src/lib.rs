mod kms;
pub use kms::{CryptoKey, Kms, KmsError};

mod secret_manager;

pub use secret_manager::{Secret, SecretManager, SecretVersion};

pub mod sync {
    pub use super::kms::sync::{CryptoKey, Kms};
    pub use super::secret_manager::sync::SecretManager;
}
