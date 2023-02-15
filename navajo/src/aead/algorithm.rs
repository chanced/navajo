use super::size::{AES_128_GCM, AES_256_GCM, CHACHA20_POLY1305, XCHACHA20_POLY1305};
use alloc::string::String;
use serde::{Deserialize, Serialize};

use super::Size;

/// Ad
#[derive(Serialize, Deserialize, PartialEq, Eq, Clone, Copy, Debug)]
#[repr(u8)]
pub enum Algorithm {
    /// https://datatracker.ietf.org/doc/html/rfc8439
    ChaCha20Poly1305,
    /// AES 128 GCM
    Aes128Gcm,
    /// AES 256 GCM
    Aes256Gcm,
    /// https://en.wikipedia.org/w/index.php?title=ChaCha20-Poly1305&section=3#XChaCha20-Poly1305_%E2%80%93_extended_nonce_variant
    XChaCha20Poly1305,
}

impl Algorithm {
    /// The length of the nonce in bytes
    pub fn size(&self) -> Size {
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
    pub fn header_len(&self) -> usize {
        self.nonce_len() + self.key_len()
    }
    pub fn streaming_nonce_prefix_len(&self) -> usize {
        self.nonce_len() - 5
    }
    pub fn streaming_header_len(&self) -> usize {
        self.header_len() + self.streaming_nonce_prefix_len() + self.key_len()
    }
}

impl core::fmt::Display for Algorithm {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Algorithm::ChaCha20Poly1305 => write!(f, "ChaCha20Poly1305"),
            Algorithm::Aes128Gcm => write!(f, "Aes128Gcm"),
            Algorithm::Aes256Gcm => write!(f, "Aes256Gcm"),
            Algorithm::XChaCha20Poly1305 => write!(f, "XChaCha20Poly1305"),
        }
    }
}
impl From<Algorithm> for u8 {
    fn from(alg: Algorithm) -> Self {
        match alg {
            Algorithm::ChaCha20Poly1305 => 0,
            Algorithm::Aes128Gcm => 1,
            Algorithm::Aes256Gcm => 2,
            Algorithm::XChaCha20Poly1305 => 3,
        }
    }
}
impl TryFrom<u8> for Algorithm {
    type Error = String;
    fn try_from(v: u8) -> Result<Self, Self::Error> {
        match v {
            0 => Ok(Algorithm::ChaCha20Poly1305),
            1 => Ok(Algorithm::Aes128Gcm),
            2 => Ok(Algorithm::Aes256Gcm),
            3 => Ok(Algorithm::XChaCha20Poly1305),
            _ => Err("invalid algorithm".into()),
        }
    }
}

// impl Algorithm {

//     /// The length of the tag in bytes
//     pub fn tag_len(&self) -> usize {
//         self.ring().tag_len()
//     }
//     /// The length of the key in bytes
//     pub fn key_len(&self) -> usize {
//         self.ring().key_len()
//     }

//     fn ring(&self) -> &'static ring::aead::Algorithm {
//         match self {
//             Algorithm::ChaCha20Poly1305 => &ring::aead::CHACHA20_POLY1305,
//             Algorithm::Aes128Gcm => &ring::aead::AES_128_GCM,
//             Algorithm::Aes256Gcm => &ring::aead::AES_256_GCM,
//         }
//     }

//     pub(super) fn load_key(&self, key: &[u8]) -> Result<LessSafeKey, ring::error::Unspecified> {
//         UnboundKey::new(self.ring(), key).map(LessSafeKey::new)
//     }
// }
