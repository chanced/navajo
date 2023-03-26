use core::str::FromStr;

use alloc::vec::Vec;
use serde::{Deserialize, Serialize};
use strum::{Display, EnumIter, IntoStaticStr};

use crate::{
    error::{InvalidAlgorithmError, KeyError},
    rand::Rng, strings::to_upper_remove_seperators,
};

const SHA2_256_KEY_LEN: usize = 32;
const SHA2_384_KEY_LEN: usize = 48;
const SHA2_512_KEY_LEN: usize = 64;
const SHA3_224_KEY_LEN: usize = 32;
const SHA3_256_KEY_LEN: usize = 32;
const SHA3_384_KEY_LEN: usize = 48;
const SHA3_512_KEY_LEN: usize = 64;
#[cfg(feature = "blake3")]
const BLAKE3_KEY_LEN: usize = 32;
#[cfg(feature = "aes")]
const AES128_KEY_LEN: usize = 16;
#[cfg(feature = "aes")]
const AES192_KEY_LEN: usize = 24;
#[cfg(feature = "aes")]
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
    #[cfg(feature = "blake3")]
    Blake3,

    #[cfg(any(feature = "ring", all(feature = "sha2", feature = "hmac")))]
    #[serde(rename = "SHA2-256")]
    #[strum(serialize = "SHA2-256")]
    Sha256,

    #[cfg(any(feature = "ring", all(feature = "sha2", feature = "hmac")))]
    #[serde(rename = "SHA2-384")]
    #[strum(serialize = "SHA2-384")]
    Sha384,

    #[cfg(any(feature = "ring", all(feature = "sha2", feature = "hmac")))]
    #[serde(rename = "SHA2-512")]
    #[strum(serialize = "SHA2-512")]
    Sha512,

    #[cfg(all(feature = "sha3", feature = "hmac"))]
    #[serde(rename = "SHA3-256")]
    #[strum(serialize = "SHA3-256")]
    Sha3_256,

    #[cfg(all(feature = "sha3", feature = "hmac"))]
    #[serde(rename = "SHA3-224")]
    #[strum(serialize = "SHA3-224")]
    Sha3_224,

    #[cfg(all(feature = "sha3", feature = "hmac"))]
    #[serde(rename = "SHA3-384")]
    #[strum(serialize = "SHA3-384")]
    Sha3_384,

    #[cfg(all(feature = "sha3", feature = "hmac"))]
    #[serde(rename = "SHA3-512")]
    #[strum(serialize = "SHA3-512")]
    Sha3_512,

    // CMAC
    #[cfg(all(feature = "aes", feature = "cmac"))]
    #[serde(rename = "AES-128")]
    #[strum(serialize = "AES-128")]
    Aes128,

    #[cfg(all(feature = "aes", feature = "cmac"))]
    #[serde(rename = "AES-192")]
    #[strum(serialize = "AES-192")]
    Aes192,

    #[cfg(all(feature = "aes", feature = "cmac"))]
    #[serde(rename = "AES-256")]
    #[strum(serialize = "AES-256")]
    Aes256,
}
impl FromStr for Algorithm {
    type Err = InvalidAlgorithmError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        
        match to_upper_remove_seperators(s).as_str() {
            #[cfg(feature = "blake3")]
            "BLAKE3" => return OK(Algorithm::Blake3),
            "SHA256" | "SHA2256" => return Ok(Algorithm::Sha256),
            "SHA384" | "SHA2384" => return Ok(Algorithm::Sha384),
            "SHA512" | "SHA2512" => return Ok(Algorithm::Sha512),
            #[cfg(all(feature = "sha3", feature = "hmac"))]
            "SHA3256" => return Ok(Algorithm::Sha3_256),
            #[cfg(all(feature = "sha3", feature = "hmac"))]
            "SHA3224" => Ok(Algorithm::Sha3_224),
            #[cfg(all(feature = "sha3", feature = "hmac"))]
            "SHA3384" => Ok(Algorithm::Sha3_384),
            #[cfg(all(feature = "sha3", feature = "hmac"))]
            "SHA3512" => Ok(Algorithm::Sha3_512),
            #[cfg(all(feature = "aes", feature = "cmac"))]
            "AES128" => Ok(Algorithm::Aes128),
            #[cfg(all(feature = "aes", feature = "cmac"))]
            "AES192" => Ok(Algorithm::Aes192),
            #[cfg(all(feature = "aes", feature = "cmac"))]
            "AES256" => Ok(Algorithm::Aes256),
            _ => Err(InvalidAlgorithmError(s.into())),
        }
    }
}

impl TryFrom<String> for Algorithm {
    type Error = InvalidAlgorithmError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Algorithm::from_str(&value)
    }
}
impl TryFrom<&String> for Algorithm {
    type Error = InvalidAlgorithmError;

    fn try_from(value: &String) -> Result<Self, Self::Error> {
        Algorithm::from_str(value)
    }
}
impl TryFrom<&str> for Algorithm {
    type Error = InvalidAlgorithmError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        Algorithm::from_str(value)
    }
}

impl Algorithm {
    pub(super) fn generate_key<R>(&self, rng: &R) -> Vec<u8>
    where
        R: Rng,
    {
        let mut key = alloc::vec![0u8; self.default_key_len()];
        rng.fill(&mut key).unwrap();
        key
    }
    pub fn tag_len(&self) -> usize {
        match self {
            #[cfg(any(feature = "ring", all(feature = "sha2", feature = "hmac")))]
            Algorithm::Sha256 => 32,
            #[cfg(any(feature = "ring", all(feature = "sha2", feature = "hmac")))]
            Algorithm::Sha384 => 48,
            #[cfg(any(feature = "ring", all(feature = "sha2", feature = "hmac")))]
            Algorithm::Sha512 => 64,
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
    pub fn validate_key_len(&self, len: usize) -> Result<(), KeyError> {
        if len == 0 {
            return Err(KeyError("key length must be greater than 0".into()));
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
                    Err("AES-128 key length must be 16 bytes".into())
                } else {
                    Ok(())
                }
            }
            #[cfg(all(feature = "aes", feature = "cmac"))]
            Algorithm::Aes192 => {
                if len != AES192_KEY_LEN {
                    Err("AES-192 key length must be 24 bytes".into())
                } else {
                    Ok(())
                }
            }
            #[cfg(all(feature = "aes", feature = "cmac"))]
            Algorithm::Aes256 => {
                if len != AES256_KEY_LEN {
                    Err("AES-256 key length must be 32 bytes".into())
                } else {
                    Ok(())
                }
            }
            _ => Ok(()), // todo: double check this
        }
    }
    pub fn default_key_len(&self) -> usize {
        match self {
            #[cfg(any(feature = "ring", all(feature = "sha2", feature = "hmac")))]
            Algorithm::Sha256 => SHA2_256_KEY_LEN,
            #[cfg(any(feature = "ring", all(feature = "sha2", feature = "hmac")))]
            Algorithm::Sha384 => SHA2_384_KEY_LEN,
            #[cfg(any(feature = "ring", all(feature = "sha2", feature = "hmac")))]
            Algorithm::Sha512 => SHA2_512_KEY_LEN,
            #[cfg(all(feature = "sha3", feature = "hmac"))]
            Algorithm::Sha3_224 => SHA3_224_KEY_LEN,
            #[cfg(all(feature = "sha3", feature = "hmac"))]
            Algorithm::Sha3_256 => SHA3_256_KEY_LEN,
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
