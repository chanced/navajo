use crate::{aead::nonce::Nonce, error::EncryptError, Buffer};

use super::{algorithm::RustCryptoAlgorithm, Algorithm};

const HEADER_LEN: usize = 5;

#[allow(clippy::large_enum_variant)]
pub(super) enum Cipher {
    #[cfg(feature = "ring")]
    Ring(RingCipher),
    RustCrypto(RustCryptoCipher),
}

impl Cipher {
    pub(super) fn encrypt_in_place<B>(
        &self,
        data: &mut B,
        aad: &[u8],
        nonce: Nonce,
    ) -> Result<(), EncryptError>
    where
        B: Buffer,
    {
        // match self {
        //     Self::RustCrypto(rc) => //rc.encrypt_in_place(nonce, aad, data),
        //     Self::Ring(ring) => ring.encrypt_in_place(nonce, aad, data),
        // }
        todo!()
    }
    pub(super) fn new(algorithm: Algorithm, key: &[u8]) -> Self {
        match algorithm {
            Algorithm::ChaCha20Poly1305 => {
                #[cfg(feature = "ring")]
                {
                    Self::Ring(RingCipher::new(&ring::aead::CHACHA20_POLY1305, key))
                }
                #[cfg(not(feature = "ring"))]
                {
                    Self::RustCrypto(RustCryptoCipher::new(
                        RustCryptoAlgorithm::ChaCha20Poly1305,
                        key,
                    ))
                }
            }
            Algorithm::Aes128Gcm => {
                #[cfg(feature = "ring")]
                {
                    Self::Ring(RingCipher::new(&ring::aead::AES_128_GCM, key))
                }
                #[cfg(not(feature = "ring"))]
                {
                    Self::RustCrypto(RustCryptoCipher::new(RustCryptoAlgorithm::Aes128Gcm, key))
                }
            }
            Algorithm::Aes256Gcm => {
                #[cfg(feature = "ring")]
                {
                    Self::Ring(RingCipher::new(&ring::aead::AES_256_GCM, key))
                }
                #[cfg(not(feature = "ring"))]
                {
                    Self::RustCrypto(RustCryptoCipher::new(RustCryptoAlgorithm::Aes256Gcm, key))
                }
            }
            Algorithm::XChaCha20Poly1305 => Self::RustCrypto(RustCryptoCipher::new(
                RustCryptoAlgorithm::XChaCha20Poly1305,
                key,
            )),
        }
    }
}

#[cfg(feature = "ring")]

pub(super) struct RingCipher(ring::aead::LessSafeKey);
impl RingCipher {
    pub(super) fn new(algorithm: &'static ring::aead::Algorithm, key: &[u8]) -> RingCipher {
        let unbounded = ring::aead::UnboundKey::new(algorithm, key).unwrap(); // safe, keys are only generated and are always the correct size
        let key = ring::aead::LessSafeKey::new(unbounded);
        RingCipher(key)
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
        // self.0.seal_in_place_append_tag(nonce.into(), aad, data)?;
        todo!()
    }
}
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
    pub(super) fn new(algorithm: RustCryptoAlgorithm, key: &[u8]) -> Self {
        match algorithm {
            #[cfg(not(feature = "ring"))]
            RustCryptoAlgorithm::ChaCha20Poly1305 => {
                use chacha20poly1305::KeyInit;
                let key = chacha20poly1305::ChaCha20Poly1305::new_from_slice(key).unwrap(); // safe: keys are always generated and the correct size
                Self::ChaCha20Poly1305(key)
            }
            #[cfg(not(feature = "ring"))]
            RustCryptoAlgorithm::Aes128Gcm => {
                use aes_gcm::KeyInit;
                let key = aes_gcm::Aes128Gcm::new_from_slice(key).unwrap(); // safe: keys are always generated and the correct size
                Self::Aes128Gcm(key)
            }
            #[cfg(not(feature = "ring"))]
            RustCryptoAlgorithm::Aes256Gcm => {
                use aes_gcm::KeyInit;
                let key = aes_gcm::Aes256Gcm::new_from_slice(key).unwrap(); // safe: keys are always generated and the correct size
                Self::Aes128Gcm(key)
            }
            RustCryptoAlgorithm::XChaCha20Poly1305 => {
                use aes_gcm::KeyInit;
                let key = chacha20poly1305::XChaCha20Poly1305::new_from_slice(key).unwrap(); // safe: keys are always generated and the correct size
                Self::XChaCha20Poly1305(key)
            }
        }
    }
}

fn prepend_header<B: Buffer>(data: &mut B, header: &[u8]) {
    let original_len = data.as_ref().len();
    let header_len = header.len();
    let shifted = data.as_ref()[original_len - header_len..].to_vec();
    data.extend(shifted.iter());
    // shifts the data to the right by header len
    let data = data.as_mut();
    #[allow(clippy::needless_range_loop)]
    for i in (0..original_len - header_len).rev() {
        data[i + header_len] = data[i];
        if i < header_len {
            data[i] = header[i];
        }
    }
}
#[cfg(test)]
mod tests {
    use alloc::vec;

    use super::*;

    #[test]
    fn test_prepend_header() {
        let header = [0, 1, 2, 3, 4];
        let mut data = vec![10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21];

        prepend_header(&mut data, &header);
        assert_eq!(
            data,
            vec![0, 1, 2, 3, 4, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21]
        )
    }
}
