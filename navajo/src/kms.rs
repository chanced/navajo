use core::{fmt::Display, pin::Pin};

use alloc::{boxed::Box, vec::Vec};
use futures::Future;

pub trait Kms {
    type EncryptError: Display + Send + Sync;
    type DecryptError: Display + Send + Sync;
    fn encrypt(
        &self,
        plaintext: &[u8],
        associated_data: &[u8],
    ) -> Pin<Box<dyn Future<Output = Result<Vec<u8>, Self::EncryptError>> + Send>>;

    fn decrypt(
        &self,
        ciphertext: &[u8],
        associated_data: &[u8],
    ) -> Pin<Box<dyn Future<Output = Result<Vec<u8>, Self::DecryptError>> + Send>>;
}

pub trait KmsSync {
    type EncryptError: Display + Send + Sync;
    type DecryptError: Display + Send + Sync;
    fn encrypt(
        &self,
        plaintext: &[u8],
        associated_data: &[u8],
    ) -> Result<Vec<u8>, Self::EncryptError>;

    fn decrypt(
        &self,
        ciphertext: &[u8],
        associated_data: &[u8],
    ) -> Result<Vec<u8>, Self::DecryptError>;
}
