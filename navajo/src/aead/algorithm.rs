use core::str::FromStr;

use crate::{
    error::InvalidAlgorithmError, keyring::KEY_ID_LEN, strings::to_upper_remove_seperators,
};

use super::{
    size::{AES_128_GCM, AES_256_GCM, CHACHA20_POLY1305, XCHACHA20_POLY1305},
    Method,
};
use alloc::string::ToString;
use serde::{Deserialize, Serialize};
use strum::{Display, EnumIter, IntoStaticStr};

use super::Size;

/// AEAD Algorithms
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
pub enum Algorithm {
    /// AES-128-GCM uses the AES block cipher with a 128-bit key and provides
    /// authenticated encryption by using the Galois/Counter Mode (GCM).
    #[serde(rename = "AES-128-GCM")]
    #[strum(serialize = "AES-128-GCM")]
    Aes128Gcm = 0,

    /// AES-256-GCM uses the AES block cipher with a 256-bit key and provides
    /// authenticated encryption by using the Galois/Counter Mode (GCM).
    #[serde(rename = "AES-256-GCM")]
    #[strum(serialize = "AES-256-GCM")]
    Aes256Gcm = 1,

    /// ChaCha20-Poly1305 combines the ChaCha20 stream cipher for encryption
    /// and the Poly1305 message authentication code for integrity protection.
    ///
    /// <https://datatracker.ietf.org/doc/html/rfc8439>
    #[serde(rename = "ChaCha20-Poly1305")]
    #[strum(serialize = "ChaCha20-Poly1305")]
    ChaCha20Poly1305 = 2,

    /// XChaCha20-Poly1305 is an extension of the ChaCha20-Poly1305
    /// authenticated encryption algorithm that uses an extended nonce for
    /// stronger security guarantees.
    ///
    /// <https://en.wikipedia.org/w/index.php?title=ChaCha20-Poly1305&section=3#XChaCha20-Poly1305_%E2%80%93_extended_nonce_variant>
    #[serde(rename = "XChaCha20-Poly1305")]
    #[strum(serialize = "XChaCha20-Poly1305")]
    XChaCha20Poly1305 = 3,
}

impl Algorithm {
    fn size(&self) -> Size {
        match self {
            Algorithm::Aes128Gcm => AES_128_GCM,
            Algorithm::Aes256Gcm => AES_256_GCM,
            Algorithm::ChaCha20Poly1305 => CHACHA20_POLY1305,
            Algorithm::XChaCha20Poly1305 => XCHACHA20_POLY1305,
        }
    }
    pub fn nonce_len(&self) -> usize {
        self.size().nonce
    }
    pub fn key_len(&self) -> usize {
        self.size().key
    }
    pub fn tag_len(&self) -> usize {
        self.size().tag
    }
    pub fn nonce_prefix_len(&self) -> usize {
        // nonce len - 4 bytes for sequence number - 1 byte for last block indicator
        self.size().nonce - 4 - 1
    }
    pub fn online_header_len(&self) -> usize {
        Method::LEN + KEY_ID_LEN + self.nonce_len()
    }
    pub fn streaming_header_len(&self) -> usize {
        Method::LEN + KEY_ID_LEN + self.nonce_prefix_len() + self.key_len()
    }
}
impl From<Algorithm> for u8 {
    fn from(alg: Algorithm) -> Self {
        alg as u8
    }
}

impl FromStr for Algorithm {
    type Err = InvalidAlgorithmError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match to_upper_remove_seperators(s).as_str() {
            "AES128GCM" => Ok(Algorithm::Aes128Gcm),
            "AES256GCM" => Ok(Algorithm::Aes256Gcm),
            "CHACHA20POLY1305" => Ok(Algorithm::ChaCha20Poly1305),
            "XCHACHA20POLY1305" => Ok(Algorithm::XChaCha20Poly1305),
            _ => Err(InvalidAlgorithmError(s.to_string())),
        }
    }
}
