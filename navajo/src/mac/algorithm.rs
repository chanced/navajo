use alloc::vec::Vec;
use serde::{Deserialize, Serialize};
use strum::{Display, EnumIter, IntoStaticStr};

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

#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    Hash,
    Serialize,
    Deserialize,
    IntoStaticStr,
    Display,
    EnumIter,
)]
#[serde(rename_all = "SCREAMING-KEBAB-CASE")]
#[strum(serialize_all = "SCREAMING-KEBAB-CASE")]
pub enum Algorithm {
    // HMAC
    #[cfg(all(feature = "sha2", feature = "hmac"))]
    Sha256,
    #[cfg(all(feature = "sha2", feature = "hmac"))]
    Sha224,
    #[cfg(all(feature = "sha2", feature = "hmac"))]
    Sha384,
    #[cfg(all(feature = "sha2", feature = "hmac"))]
    Sha512,
    #[cfg(all(feature = "sha2", feature = "hmac"))]
    Sha512_224,
    #[cfg(all(feature = "sha2", feature = "hmac"))]
    Sha512_256,
    #[cfg(all(feature = "sha2", feature = "hmac"))]
    Sha3_256,
    #[cfg(all(feature = "sha3", feature = "hmac"))]
    Sha3_224,
    #[cfg(all(feature = "sha3", feature = "hmac"))]
    Sha3_384,
    #[cfg(all(feature = "sha3", feature = "hmac"))]
    Sha3_512,
    #[cfg(feature = "blake3")]
    #[serde(rename="BLAKE3")]
    #[strum(serialize="BLAKE3")]
    Blake3,

    // CMAC
    #[cfg(all(feature = "aes", feature = "cmac"))]
    Aes128,
    #[cfg(all(feature = "aes", feature = "cmac"))]
    Aes192,
    #[cfg(all(feature = "aes", feature = "cmac"))]
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
            #[cfg(all(feature = "sha2", feature = "hmac"))]
            Algorithm::Sha256 => 32,
            #[cfg(all(feature = "sha2", feature = "hmac"))]
            Algorithm::Sha224 => 28,
            #[cfg(all(feature = "sha2", feature = "hmac"))]
            Algorithm::Sha384 => 48,
            #[cfg(all(feature = "sha2", feature = "hmac"))]
            Algorithm::Sha512 => 64,
            #[cfg(all(feature = "sha2", feature = "hmac"))]
            Algorithm::Sha512_224 => 28,
            #[cfg(all(feature = "sha2", feature = "hmac"))]
            Algorithm::Sha512_256 => 32,
            #[cfg(all(feature = "sha3", feature = "hmac"))]
            Algorithm::Sha3_256 => 32,
            #[cfg(all(feature = "sha3", feature = "hmac"))]
            Algorithm::Sha3_224 => 28,
            #[cfg(all(feature = "sha3", feature = "hmac"))]
            Algorithm::Sha3_384 => 48,
            #[cfg(all(feature = "sha3", feature = "hmac"))]
            Algorithm::Sha3_512 => 64,
            #[cfg(feature = "blake3")]
            Algorithm::Blake3 => 32,
            #[cfg(all(feature = "aes", feature = "cmac"))]
            Algorithm::Aes128 => 16,
            #[cfg(all(feature = "aes", feature = "cmac"))]
            Algorithm::Aes192 => 18,
            #[cfg(all(feature = "aes", feature = "cmac"))]
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
            #[cfg(all(feature = "aes", feature = "cmac"))]
            Algorithm::Aes128 => {
                if len != AES128_KEY_LEN {
                    Err(InvalidKeyLength)
                } else {
                    Ok(())
                }
            }
            #[cfg(all(feature = "aes", feature = "cmac"))]
            Algorithm::Aes192 => {
                if len != AES192_KEY_LEN {
                    Err(InvalidKeyLength)
                } else {
                    Ok(())
                }
            }
            #[cfg(all(feature = "aes", feature = "cmac"))]
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
            #[cfg(all(feature = "sha2", feature = "hmac"))]
            Algorithm::Sha256 => SHA2_256_KEY_LEN,
            #[cfg(all(feature = "sha2", feature = "hmac"))]
            Algorithm::Sha224 => SHA2_224_KEY_LEN,
            #[cfg(all(feature = "sha2", feature = "hmac"))]
            Algorithm::Sha384 => SHA2_384_KEY_LEN,
            #[cfg(all(feature = "sha2", feature = "hmac"))]
            Algorithm::Sha512 => SHA2_512_KEY_LEN,
            #[cfg(all(feature = "sha2", feature = "hmac"))]
            Algorithm::Sha512_224 => SHA2_512_224_KEY_LEN,
            #[cfg(all(feature = "sha2", feature = "hmac"))]
            Algorithm::Sha512_256 => SHA2_512_256_KEY_LEN,
            #[cfg(all(feature = "sha3", feature = "hmac"))]
            Algorithm::Sha3_256 => SHA3_256_KEY_LEN,
            #[cfg(all(feature = "sha3", feature = "hmac"))]
            Algorithm::Sha3_224 => SHA3_224_KEY_LEN,
            #[cfg(all(feature = "sha3", feature = "hmac"))]
            Algorithm::Sha3_384 => SHA3_384_KEY_LEN,
            #[cfg(all(feature = "sha3", feature = "hmac"))]
            Algorithm::Sha3_512 => SHA3_512_KEY_LEN,
            #[cfg(feature = "blake3")]
            Algorithm::Blake3 => BLAKE3_KEY_LEN,
            #[cfg(all(feature = "aes", feature = "cmac"))]
            Algorithm::Aes128 => AES128_KEY_LEN,
            #[cfg(all(feature = "aes", feature = "cmac"))]
            Algorithm::Aes192 => AES192_KEY_LEN,
            #[cfg(all(feature = "aes", feature = "cmac"))]
            Algorithm::Aes256 => AES256_KEY_LEN,
        }
    }
}

// impl core::fmt::Display for Algorithm {
//     fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
//         match self {
//             #[cfg(all(feature = "sha2", feature = "hmac"))]
//             Algorithm::Sha256 => write!(f, "SHA256"),
//             #[cfg(all(feature = "sha2", feature = "hmac"))]
//             Algorithm::Sha224 => write!(f, "SHA224"),
//             #[cfg(all(feature = "sha2", feature = "hmac"))]
//             Algorithm::Sha384 => write!(f, "SHA384"),
//             #[cfg(all(feature = "sha2", feature = "hmac"))]
//             Algorithm::Sha512 => write!(f, "SHA512"),
//             #[cfg(all(feature = "sha2", feature = "hmac"))]
//             Algorithm::Sha512_224 => write!(f, "SHA512_224"),
//             #[cfg(all(feature = "sha2", feature = "hmac"))]
//             Algorithm::Sha512_256 => write!(f, "SHA512_256"),
//             #[cfg(all(feature = "sha3", feature = "hmac"))]
//             Algorithm::Sha3_256 => write!(f, "SHA3_256"),
//             #[cfg(all(feature = "sha3", feature = "hmac"))]
//             Algorithm::Sha3_224 => write!(f, "SHA3_224"),
//             #[cfg(all(feature = "sha3", feature = "hmac"))]
//             Algorithm::Sha3_384 => write!(f, "SHA3_384"),
//             #[cfg(all(feature = "sha3", feature = "hmac"))]
//             Algorithm::Sha3_512 => write!(f, "SHA3_512"),
//             #[cfg(feature = "blake3")]
//             Algorithm::Blake3 => write!(f, "BLAKE3"),
//             #[cfg(all(feature = "aes", feature = "cmac"))]
//             Algorithm::Aes128 => write!(f, "AES128"),
//             #[cfg(all(feature = "aes", feature = "cmac"))]
//             Algorithm::Aes192 => write!(f, "AES192"),
//             #[cfg(all(feature = "aes", feature = "cmac"))]
//             Algorithm::Aes256 => write!(f, "AES256"),
//         }
//     }
// }
