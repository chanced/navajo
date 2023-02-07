use alloc::vec::{self, Vec};
use random::RngCore;
use serde_repr::{Deserialize_repr, Serialize_repr};

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

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize_repr, Deserialize_repr)]
#[repr(u8)]
pub enum Algorithm {
    // HMAC
    #[cfg(feature = "hmac_sha2")]
    Sha256 = 0,
    #[cfg(feature = "hmac_sha2")]
    Sha224 = 1,
    #[cfg(feature = "hmac_sha2")]
    Sha384 = 2,
    #[cfg(feature = "hmac_sha2")]
    Sha512 = 3,
    #[cfg(feature = "hmac_sha2")]
    Sha2_512_224 = 4,
    #[cfg(feature = "hmac_sha2")]
    Sha512_256 = 5,
    #[cfg(feature = "hmac_sha3")]
    Sha3_256 = 6,
    #[cfg(feature = "hmac_sha3")]
    Sha3_224 = 7,
    #[cfg(feature = "hmac_sha3")]
    Sha3_384 = 8,
    #[cfg(feature = "hmac_sha3")]
    Sha3_512 = 9,
    #[cfg(feature = "blake3")]
    Blake3 = 10,
    // leaving room for other hmac algorithms
    // CMAC
    #[cfg(feature = "cmac_aes")]
    Aes128 = 128,
    #[cfg(feature = "cmac_aes")]
    Aes192 = 129,
    #[cfg(feature = "cmac_aes")]
    Aes256 = 130,
}

impl Algorithm {
    pub(super) fn generate_key(&self) -> Vec<u8> {
        let mut key = alloc::vec![0u8; self.default_key_len()];
        crate::rand::fill(&mut key);
        key
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
            Algorithm::Sha2_512_224 => SHA2_512_224_KEY_LEN,
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
