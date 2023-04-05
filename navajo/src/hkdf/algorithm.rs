use core::str::FromStr;

use alloc::string::{String, ToString};
use serde::{Deserialize, Serialize};

use crate::{error::InvalidAlgorithmError, strings::to_upper_remove_seperators};

/// HKDF algorithms
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum Algorithm {
    #[cfg(any(feature = "ring", all(feature = "sha2", feature = "hmac")))]
    Sha256,
    #[cfg(any(feature = "ring", all(feature = "sha2", feature = "hmac")))]
    Sha384,
    #[cfg(any(feature = "ring", all(feature = "sha2", feature = "hmac")))]
    Sha512,
    #[cfg(all(feature = "sha3", feature = "hmac"))]
    Sha3_256,
    #[cfg(all(feature = "sha3", feature = "hmac"))]
    Sha3_224,
    #[cfg(all(feature = "sha3", feature = "hmac"))]
    Sha3_384,
    #[cfg(all(feature = "sha3", feature = "hmac"))]
    Sha3_512,
}

impl Algorithm {
    pub fn output_len(&self) -> usize {
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
        }
    }
}
#[cfg(feature = "ring")]
impl From<Algorithm> for ring::hkdf::Algorithm {
    fn from(value: Algorithm) -> Self {
        match value {
            Algorithm::Sha256 => ring::hkdf::HKDF_SHA256,
            Algorithm::Sha384 => ring::hkdf::HKDF_SHA384,
            Algorithm::Sha512 => ring::hkdf::HKDF_SHA512,
            _ => unreachable!("ring only supports Sha256, Sha384, and Sha512"),
        }
    }
}

impl FromStr for Algorithm {
    type Err = InvalidAlgorithmError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match to_upper_remove_seperators(s).as_str() {
            #[cfg(any(feature = "ring", all(feature = "sha2", feature = "hmac")))]
            "SHA256" | "SHA2256" => Ok(Algorithm::Sha256),
            #[cfg(any(feature = "ring", all(feature = "sha2", feature = "hmac")))]
            "SHA384" | "SHA2384" => Ok(Algorithm::Sha384),
            #[cfg(any(feature = "ring", all(feature = "sha2", feature = "hmac")))]
            "SHA512" | "SHA2512" => Ok(Algorithm::Sha512),
            #[cfg(all(feature = "sha3", feature = "hmac"))]
            "SHA3256" => Ok(Algorithm::Sha3_256),
            #[cfg(all(feature = "sha3", feature = "hmac"))]
            "SHA3224" => Ok(Algorithm::Sha3_224),
            #[cfg(all(feature = "sha3", feature = "hmac"))]
            "SHA3384" => Ok(Algorithm::Sha3_384),
            #[cfg(all(feature = "sha3", feature = "hmac"))]
            "SHA3512" => Ok(Algorithm::Sha3_512),
            _ => Err(InvalidAlgorithmError(s.to_string())),
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
