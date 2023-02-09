use alloc::vec::Vec;
use serde::{Deserialize, Serialize};

use crate::error::InvalidKeyLength;

const SHA2_256_KEY_LEN: usize = 32;
const SHA2_224_KEY_LEN: usize = 32;
const SHA2_384_KEY_LEN: usize = 48;
const SHA2_512_KEY_LEN: usize = 64;
const SHA2_512_224_KEY_LEN: usize = 64;
const SHA2_512_256_KEY_LEN: usize = 64;
const SHA3_224_KEY_LEN: usize = 32;
const SHA3_256_KEY_LEN: usize = 32;
const SHA3_384_KEY_LEN: usize = 48;
const SHA3_512_KEY_LEN: usize = 64;
const BLAKE3_KEY_LEN: usize = 32;
const AES128_KEY_LEN: usize = 16;
const AES192_KEY_LEN: usize = 24;
const AES256_KEY_LEN: usize = 32;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[repr(u8)]
pub enum Algorithm {
    // HMAC
    #[cfg(feature = "hmac_sha2")]
    Sha256,
    #[cfg(feature = "hmac_sha2")]
    Sha224,
    #[cfg(feature = "hmac_sha2")]
    Sha384,
    #[cfg(feature = "hmac_sha2")]
    Sha512,
    #[cfg(feature = "hmac_sha2")]
    Sha512_224,
    #[cfg(feature = "hmac_sha2")]
    Sha512_256,
    #[cfg(feature = "hmac_sha3")]
    Sha3_256,
    #[cfg(feature = "hmac_sha3")]
    Sha3_224,
    #[cfg(feature = "hmac_sha3")]
    Sha3_384,
    #[cfg(feature = "hmac_sha3")]
    Sha3_512,
    #[cfg(feature = "blake3")]
    Blake3,

    // CMAC
    #[cfg(feature = "cmac_aes")]
    Aes128,
    #[cfg(feature = "cmac_aes")]
    Aes192,
    #[cfg(feature = "cmac_aes")]
    Aes256,
}

impl Algorithm {
    pub(super) fn generate_key(&self) -> Vec<u8> {
        let mut key = alloc::vec![0u8; self.default_key_len()];
        crate::rand::fill(&mut key);
        key
    }
    pub fn tag_len(&self) -> usize {
        match self {
            #[cfg(feature = "hmac_sha2")]
            Algorithm::Sha256 => 32,
            Algorithm::Sha224 => 28,
            Algorithm::Sha384 => 48,
            Algorithm::Sha512 => 64,
            Algorithm::Sha512_224 => 28,
            Algorithm::Sha512_256 => 32,
            Algorithm::Sha3_256 => 32,
            Algorithm::Sha3_224 => 28,
            Algorithm::Sha3_384 => 48,
            Algorithm::Sha3_512 => 64,
            Algorithm::Blake3 => 32,
            Algorithm::Aes128 => 16,
            Algorithm::Aes192 => 18,
            Algorithm::Aes256 => 32,
        }
    }
    pub fn validate_key_len(&self, len: usize) -> Result<(), InvalidKeyLength> {
        if len == 0 {
            return Err(InvalidKeyLength);
        }
        match self {
            #[cfg(feature = "blake")]
            Algorithm::Blake3 => {
                if len != BLAKE3_KEY_LEN {
                    return Err(InvalidKeyLength);
                }
            }
            #[cfg(feature = "cmac_aes")]
            Algorithm::Aes128 => {
                if len != AES128_KEY_LEN {
                    Err(InvalidKeyLength)
                } else {
                    Ok(())
                }
            }
            #[cfg(feature = "cmac_aes")]
            Algorithm::Aes192 => {
                if len != AES192_KEY_LEN {
                    Err(InvalidKeyLength)
                } else {
                    Ok(())
                }
            }
            #[cfg(feature = "cmac_aes")]
            Algorithm::Aes256 => {
                if len != AES256_KEY_LEN {
                    Err(InvalidKeyLength)
                } else {
                    Ok(())
                }
            }
            _ => Ok(()), // todo: double check this
        }
    }
    pub fn default_key_len(&self) -> usize {
        match self {
            #[cfg(feature = "hmac_sha2")]
            Algorithm::Sha256 => SHA2_256_KEY_LEN,
            #[cfg(feature = "hmac_sha2")]
            Algorithm::Sha224 => SHA2_224_KEY_LEN,
            #[cfg(feature = "hmac_sha2")]
            Algorithm::Sha384 => SHA2_384_KEY_LEN,
            #[cfg(feature = "hmac_sha2")]
            Algorithm::Sha512 => SHA2_512_KEY_LEN,
            #[cfg(feature = "hmac_sha2")]
            Algorithm::Sha512_224 => SHA2_512_224_KEY_LEN,
            #[cfg(feature = "hmac_sha2")]
            Algorithm::Sha512_256 => SHA2_512_256_KEY_LEN,
            #[cfg(feature = "hmac_sha3")]
            Algorithm::Sha3_256 => SHA3_256_KEY_LEN,
            #[cfg(feature = "hmac_sha3")]
            Algorithm::Sha3_224 => SHA3_224_KEY_LEN,
            #[cfg(feature = "hmac_sha3")]
            Algorithm::Sha3_384 => SHA3_384_KEY_LEN,
            #[cfg(feature = "hmac_sha3")]
            Algorithm::Sha3_512 => SHA3_512_KEY_LEN,
            #[cfg(feature = "blake3")]
            Algorithm::Blake3 => BLAKE3_KEY_LEN,
            #[cfg(feature = "cmac_aes")]
            Algorithm::Aes128 => AES128_KEY_LEN,
            #[cfg(feature = "cmac_aes")]
            Algorithm::Aes192 => AES192_KEY_LEN,
            #[cfg(feature = "cmac_aes")]
            Algorithm::Aes256 => AES256_KEY_LEN,
        }
    }
}
