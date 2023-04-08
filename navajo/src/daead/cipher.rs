use rust_crypto_aead::KeyInit;

use crate::{
    buffer::RcBuffer,
    error::{DecryptDeterministicallyError, EncryptDeterministicallyError, KeyError},
    Aad, Buffer,
};

use super::Algorithm;
use aes_siv::siv::Aes256Siv;

const AES_BLOCK_SIZE: usize = 16;

pub(super) struct Cipher(Aes256Siv);

impl Cipher {
    pub(super) fn new(algorithm: Algorithm, key: &[u8]) -> Result<Self, KeyError> {
        if key.len() != algorithm.key_len() {
            return Err(KeyError("invalid key length".to_string()));
        }
        let cipher = aes_siv::siv::Aes256Siv::new_from_slice(key)
            .map_err(|err| KeyError(err.to_string()))?;
        Ok(Self(cipher))
    }

    pub(super) fn encrypt_in_place<A, B>(
        &mut self,
        aad: Aad<A>,
        plaintext: &mut B,
    ) -> Result<(), EncryptDeterministicallyError>
    where
        A: AsRef<[u8]>,
        B: Buffer,
    {
        if plaintext.len() > (isize::MAX as usize) - AES_BLOCK_SIZE {
            return Err(EncryptDeterministicallyError::PlaintextTooLong);
        }
        let mut buf = RcBuffer(plaintext);
        self.0
            .encrypt_in_place([aad], &mut buf)
            .map_err(|_| EncryptDeterministicallyError::Unspecified)?;
        Ok(())
    }

    pub(super) fn decrypt_in_place<A, B>(
        &mut self,
        aad: Aad<A>,
        ciphertext: &mut B,
    ) -> Result<(), DecryptDeterministicallyError>
    where
        A: AsRef<[u8]>,
        B: Buffer,
    {
        if ciphertext.len() < aes_siv::siv::IV_SIZE {
            return Err(DecryptDeterministicallyError::CiphertextTooShort);
        }

        let mut buf = RcBuffer(ciphertext);
        self.0
            .decrypt_in_place([aad], &mut buf)
            .map_err(|_| DecryptDeterministicallyError::Unspecified)
    }
}
