use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum Algorithm {
    HkdfSha256,
    HkdfSha224,
    HkdfSha384,
    HkdfSha512,
    HkdfSha512_224,
    HkdfSha512_256,
    HkdfSha3_256,
    HkdfSha3_224,
    HkdfSha3_384,
    HkdfSha3_512,
}

impl Algorithm {
    pub fn output_len(&self) -> usize {
        match self {
            Algorithm::HkdfSha256 => 32,
            Algorithm::HkdfSha224 => 28,
            Algorithm::HkdfSha384 => 48,
            Algorithm::HkdfSha512 => 64,
            Algorithm::HkdfSha512_224 => 28,
            Algorithm::HkdfSha512_256 => 32,
            Algorithm::HkdfSha3_256 => 32,
            Algorithm::HkdfSha3_224 => 28,
            Algorithm::HkdfSha3_384 => 48,
            Algorithm::HkdfSha3_512 => 64,
        }
    }
}
#[cfg(feature = "ring")]
impl From<Algorithm> for ring::hkdf::Algorithm {
    fn from(value: Algorithm) -> Self {
        match value {
            Algorithm::HkdfSha256 => ring::hkdf::HKDF_SHA256,
            Algorithm::HkdfSha384 => ring::hkdf::HKDF_SHA384,
            Algorithm::HkdfSha512 => ring::hkdf::HKDF_SHA512,
            _ => unreachable!("ring only supports Sha256, Sha384, and Sha512"),
        }
    }
}
