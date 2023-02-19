use crate::{
    aead::nonce::Nonce,
    buffer::RcBuffer,
    error::{DecryptError, EncryptError},
    Buffer,
};

use super::Algorithm;

#[allow(clippy::large_enum_variant)]
pub(super) enum Cipher {
    #[cfg(feature = "ring")]
    Ring(RingCipher),
    RustCrypto(RustCryptoCipher),
}
impl core::fmt::Debug for Cipher {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_tuple("Cipher").field(&self.algorithm()).finish()
    }
}
impl Cipher {
    pub(super) fn algorithm(&self) -> Algorithm {
        match self {
            Self::RustCrypto(rc) => rc.algorithm(),
            #[cfg(feature = "ring")]
            Self::Ring(ring) => ring.algorithm(),
        }
    }
    pub(super) fn new(algorithm: Algorithm, key: &[u8]) -> Self {
        match algorithm {
            Algorithm::ChaCha20Poly1305 => {
                #[cfg(feature = "ring")]
                {
                    Self::Ring(RingCipher::new(
                        algorithm,
                        &ring::aead::CHACHA20_POLY1305,
                        key,
                    ))
                }
                #[cfg(not(feature = "ring"))]
                {
                    Self::RustCrypto(RustCryptoCipher::new_chacha20_poly1305(key))
                }
            }
            Algorithm::Aes128Gcm => {
                #[cfg(feature = "ring")]
                {
                    Self::Ring(RingCipher::new(algorithm, &ring::aead::AES_128_GCM, key))
                }
                #[cfg(not(feature = "ring"))]
                {
                    Self::RustCrypto(RustCryptoCipher::new_aes_128_gcm(key))
                }
            }
            Algorithm::Aes256Gcm => {
                #[cfg(feature = "ring")]
                {
                    Self::Ring(RingCipher::new(algorithm, &ring::aead::AES_256_GCM, key))
                }
                #[cfg(not(feature = "ring"))]
                {
                    Self::RustCrypto(RustCryptoCipher::new_aes_256_gcm(key))
                }
            }
            Algorithm::XChaCha20Poly1305 => {
                Self::RustCrypto(RustCryptoCipher::new_x_chacha20_poly1305(key))
            }
        }
    }
    pub(super) fn decrypt_in_place<B>(
        &self,
        nonce: Nonce,
        aad: &[u8],
        data: &mut B,
    ) -> Result<(), DecryptError>
    where
        B: Buffer,
    {
        match self {
            Self::RustCrypto(rc) => rc.decrypt_in_place(nonce, aad, data),
            #[cfg(feature = "ring")]
            Self::Ring(ring) => ring.decrypt_in_place(nonce, aad, data),
        }
    }
    pub(super) fn encrypt_in_place<B>(
        &self,
        nonce: Nonce,
        aad: &[u8],
        data: &mut B,
    ) -> Result<(), EncryptError>
    where
        B: Buffer,
    {
        match self {
            Self::RustCrypto(rc) => rc.encrypt_in_place(nonce, aad, data),
            #[cfg(feature = "ring")]
            Self::Ring(ring) => ring.encrypt_in_place(nonce, aad, data),
        }
    }
}

#[cfg(feature = "ring")]
pub(super) struct RingCipher {
    key: ring::aead::LessSafeKey,
    algorithm: Algorithm,
}

#[cfg(feature = "ring")]
impl RingCipher {
    pub(super) fn new(
        algorithm: Algorithm,
        ring_algorithm: &'static ring::aead::Algorithm,
        key: &[u8],
    ) -> RingCipher {
        let unbounded = ring::aead::UnboundKey::new(ring_algorithm, key).unwrap(); // safe, keys are only generated and are always the correct size
        let key = ring::aead::LessSafeKey::new(unbounded);
        RingCipher { key, algorithm }
    }
    fn algorithm(&self) -> Algorithm {
        self.algorithm
    }
    pub(super) fn encrypt_in_place<B>(
        &self,
        nonce: Nonce,
        aad: &[u8],
        data: &mut B,
    ) -> Result<(), EncryptError>
    where
        B: Buffer,
    {
        let aad = ring::aead::Aad::from(aad);
        self.key.seal_in_place_append_tag(nonce.into(), aad, data)?;
        Ok(())
    }
    pub(super) fn decrypt_in_place<B>(
        &self,
        nonce: Nonce,
        aad: &[u8],
        data: &mut B,
    ) -> Result<(), DecryptError>
    where
        B: Buffer,
    {
        let aad = ring::aead::Aad::from(aad);
        self.key.open_in_place(nonce.into(), aad, data.as_mut())?;
        data.truncate(data.len() - self.key.algorithm().tag_len());
        Ok(())
    }
}

// todo: should some(all?) of these be boxed?
#[allow(clippy::large_enum_variant)]
pub(super) enum RustCryptoCipher {
    #[cfg(not(feature = "ring"))]
    Aes128Gcm(aes_gcm::Aes128Gcm),
    #[cfg(not(feature = "ring"))]
    Aes256Gcm(aes_gcm::Aes256Gcm),
    #[cfg(not(feature = "ring"))]
    ChaCha20Poly1305(chacha20poly1305::ChaCha20Poly1305),
    XChaCha20Poly1305(chacha20poly1305::XChaCha20Poly1305),
}
impl RustCryptoCipher {
    #[cfg(not(feature = "ring"))]
    fn new_chacha20_poly1305(key: &[u8]) -> Self {
        use chacha20poly1305::KeyInit;
        let key = chacha20poly1305::ChaCha20Poly1305::new_from_slice(key).unwrap(); // safe: keys are always generated and the correct size
        Self::ChaCha20Poly1305(key)
    }
    fn new_x_chacha20_poly1305(key: &[u8]) -> Self {
        use chacha20poly1305::KeyInit;
        let key = chacha20poly1305::XChaCha20Poly1305::new_from_slice(key).unwrap(); // safe: keys are always generated and the correct size
        Self::XChaCha20Poly1305(key)
    }
    #[cfg(not(feature = "ring"))]
    fn new_aes_128_gcm(key: &[u8]) -> Self {
        use aes_gcm::KeyInit;
        let key = aes_gcm::Aes128Gcm::new_from_slice(key).unwrap(); // safe: keys are always generated and the correct size
        Self::Aes128Gcm(key)
    }
    #[cfg(not(feature = "ring"))]
    fn new_aes_256_gcm(key: &[u8]) -> Self {
        use aes_gcm::KeyInit;
        let key = aes_gcm::Aes256Gcm::new_from_slice(key).unwrap(); // safe: keys are always generated and the correct size
        Self::Aes256Gcm(key)
    }
    pub(super) fn encrypt_in_place<B>(
        &self,
        nonce: Nonce,
        aad: &[u8],
        data: &mut B,
    ) -> Result<(), EncryptError>
    where
        B: Buffer,
    {
        let mut buffer = RcBuffer(data);
        match self {
            #[cfg(not(feature = "ring"))]
            Self::Aes128Gcm(aes) => {
                use aes_gcm::aead::AeadInPlace;
                aes.encrypt_in_place(&nonce.into(), aad, &mut buffer)
            }
            #[cfg(not(feature = "ring"))]
            Self::Aes256Gcm(aes) => {
                use aes_gcm::aead::AeadInPlace;
                aes.encrypt_in_place(&nonce.into(), aad, &mut buffer)
            }
            #[cfg(not(feature = "ring"))]
            Self::ChaCha20Poly1305(chacha) => {
                use chacha20poly1305::aead::AeadInPlace;
                chacha.encrypt_in_place(&nonce.into(), aad, &mut buffer)
            }
            Self::XChaCha20Poly1305(cipher) => {
                use chacha20poly1305::aead::AeadInPlace;
                cipher.encrypt_in_place(&nonce.into(), aad, &mut buffer)
            }
        }?;
        Ok(())
    }
    pub(super) fn decrypt_in_place<B>(
        &self,
        nonce: Nonce,
        aad: &[u8],
        data: &mut B,
    ) -> Result<(), DecryptError>
    where
        B: Buffer,
    {
        let mut buffer = RcBuffer(data);
        match self {
            #[cfg(not(feature = "ring"))]
            Self::Aes128Gcm(aes) => {
                use aes_gcm::aead::AeadInPlace;
                aes.decrypt_in_place(&nonce.into(), aad, &mut buffer)
            }
            #[cfg(not(feature = "ring"))]
            Self::Aes256Gcm(aes) => {
                use aes_gcm::aead::AeadInPlace;
                aes.decrypt_in_place(&nonce.into(), aad, &mut buffer)
            }
            #[cfg(not(feature = "ring"))]
            Self::ChaCha20Poly1305(chacha) => {
                use chacha20poly1305::aead::AeadInPlace;
                chacha.decrypt_in_place(&nonce.into(), aad, &mut buffer)
            }
            Self::XChaCha20Poly1305(cipher) => {
                use chacha20poly1305::aead::AeadInPlace;
                cipher.decrypt_in_place(&nonce.into(), aad, &mut buffer)
            }
        }?;
        Ok(())
    }

    fn algorithm(&self) -> Algorithm {
        match self {
            #[cfg(not(feature = "ring"))]
            Self::Aes128Gcm(_) => Algorithm::Aes128Gcm,
            #[cfg(not(feature = "ring"))]
            Self::Aes256Gcm(_) => Algorithm::Aes256Gcm,
            #[cfg(not(feature = "ring"))]
            Self::ChaCha20Poly1305(_) => Algorithm::ChaCha20Poly1305,
            Self::XChaCha20Poly1305(_) => Algorithm::XChaCha20Poly1305,
        }
    }
}
