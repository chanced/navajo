mod kms;
pub use kms::{Kms, KmsError};

mod secret_manager;

pub use secret_manager::SecretManager;

pub mod sync {
    pub use super::kms::sync::{Key, Kms};
}
