use serde::{Deserialize, Serialize};

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
