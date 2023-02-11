use ring::error::Unspecified;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::error::UnspecifiedError;

use super::Algorithm;

#[allow(clippy::large_enum_variant)]
pub(super) enum Cipher {
    #[cfg(feature = "ring")]
    Ring(RingCipher),
    RustCrypto(RustCryptoCipher),
}

impl Cipher {
    pub(super) fn new(algorithm: Algorithm, key: &[u8]) -> Self {
        match algorithm {
            Algorithm::ChaCha20Poly1305 => {
                #[cfg(feature = "ring")]
                {
                    let ring_key = ring_key(&ring::aead::CHACHA20_POLY1305, key);
                    Self::Ring(RingCipher(ring_key))
                }
                #[cfg(not(feature = "ring"))]
                {
                    use chacha20poly1305::KeyInit;
                    let rust_crypto_key =
                        chacha20poly1305::ChaCha20Poly1305::new_from_slice(key.into()).unwrap(); // safe: keys are always generated and the correct size
                    Self::RustCrypto(RustCryptoCipher::ChaCha20Poly1305(rust_crypto_key))
                }
            }
            Algorithm::Aes128Gcm => {
                #[cfg(feature = "ring")]
                {
                    let ring_key = ring_key(&ring::aead::AES_128_GCM, key);
                    Self::Ring(RingCipher(ring_key))
                }
                #[cfg(not(feature = "ring"))]
                {
                    use aes_gcm::KeyInit;
                    let rust_crypto_key = aes_gcm::Aes128Gcm::new_from_slice(key.into()).unwrap(); // safe: keys are always generated and the correct size
                    Ok(Self::RustCrypto(RustCryptoCipher::Aes128Gcm(
                        rust_crypto_key,
                    )))
                }
            }
            Algorithm::Aes256Gcm => {
                #[cfg(feature = "ring")]
                {
                    let ring_key = ring_key(&ring::aead::AES_256_GCM, key);
                    Self::Ring(RingCipher(ring_key))
                }
                #[cfg(not(feature = "ring"))]
                {
                    use aes_gcm::KeyInit;
                    let rust_crypto_key = aes_gcm::Aes256Gcm::new_from_slice(key).unwrap(); // safe: keys are always generated and the correct size
                    Ok(Self::RustCrypto(RustCryptoCipher::Aes256Gcm(
                        rust_crypto_key,
                    )))
                }
            }
            Algorithm::XChaCha20Poly1305 => {
                use chacha20poly1305::KeyInit;
                let rust_crypto_key =
                    chacha20poly1305::XChaCha20Poly1305::new_from_slice(key).unwrap(); // safe: keys are always generated and the correct size
                Self::RustCrypto(RustCryptoCipher::XChaCha20Poly1305(rust_crypto_key))
            }
        }
    }
}

#[cfg(feature = "ring")]
fn ring_key(algorithm: &'static ring::aead::Algorithm, key: &[u8]) -> ring::aead::LessSafeKey {
    let unbounded = ring::aead::UnboundKey::new(algorithm, key).unwrap(); // safe, keys are only generated and are always the correct size
    let less_safe = ring::aead::LessSafeKey::new(unbounded);
    less_safe
}

pub(super) struct RingCipher(ring::aead::LessSafeKey);

pub(super) enum RustCryptoCipher {
    #[cfg(not(feature = "ring"))]
    Aes128Gcm(aes_gcm::Aes128Gcm),
    #[cfg(not(feature = "ring"))]
    Aes256Gcm(aes_gcm::Aes256Gcm),
    // #[cfg(not(feature = "ring"))]
    ChaCha20Poly1305(chacha20poly1305::ChaCha20Poly1305),

    XChaCha20Poly1305(chacha20poly1305::XChaCha20Poly1305),
}
