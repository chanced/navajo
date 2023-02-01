use ring::aead::{LessSafeKey, UnboundKey};
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, PartialEq, Eq, Clone, Copy, Debug)]
#[repr(u8)]
#[serde(try_from = "u8", into = "u8")]
pub enum Algorithm {
    ChaCha20Poly1305,
    Aes128Gcm,
    Aes256Gcm,
}
impl From<Algorithm> for u8 {
    fn from(alg: Algorithm) -> Self {
        match alg {
            Algorithm::ChaCha20Poly1305 => 0,
            Algorithm::Aes128Gcm => 1,
            Algorithm::Aes256Gcm => 2,
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
            _ => Err("invalid algorithm".into()),
        }
    }
}
impl Algorithm {
    /// The length of the nonce in bytes
    pub fn nonce_len(&self) -> usize {
        self.ring().nonce_len()
    }
    /// The length of the nonce prefix in bytes defined by the nonce length
    /// minus 4 bytes (u16) for the sequence number and 1 byte last block
    /// indicator
    pub fn nonce_prefix_len(&self) -> usize {
        self.ring().nonce_len() - 4 - 1
    }

    /// The length of the tag in bytes
    pub fn tag_len(&self) -> usize {
        self.ring().tag_len()
    }
    /// The length of the key in bytes
    pub fn key_len(&self) -> usize {
        self.ring().key_len()
    }

    fn ring(&self) -> &'static ring::aead::Algorithm {
        match self {
            Algorithm::ChaCha20Poly1305 => &ring::aead::CHACHA20_POLY1305,
            Algorithm::Aes128Gcm => &ring::aead::AES_128_GCM,
            Algorithm::Aes256Gcm => &ring::aead::AES_256_GCM,
        }
    }

    pub(super) fn load_key(&self, key: &[u8]) -> Result<LessSafeKey, ring::error::Unspecified> {
        UnboundKey::new(self.ring(), key).map(LessSafeKey::new)
    }
}
