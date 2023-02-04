use serde::{Deserialize, Serialize};

use crate::error::InvalidAlgorithm;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "u8", into = "u8")]
pub enum Algorithm {
    Sha256 = 0,
    Sha384 = 1,
    Sha512 = 2,
    Blake3 = 3,
}

impl From<Algorithm> for u8 {
    fn from(algorithm: Algorithm) -> Self {
        match algorithm {
            Algorithm::Sha256 => 0,
            Algorithm::Sha384 => 1,
            Algorithm::Sha512 => 2,
            Algorithm::Blake3 => 3,
        }
    }
}

impl TryFrom<u8> for Algorithm {
    type Error = InvalidAlgorithm;
    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Algorithm::Sha256),
            1 => Ok(Algorithm::Sha384),
            2 => Ok(Algorithm::Sha512),
            _ => Err(InvalidAlgorithm(value)),
        }
    }
}
