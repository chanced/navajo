use serde_repr::{Deserialize_repr, Serialize_repr};

const SHA2_256_KEY_LEN: usize = 32;
const SHA2_224_KEY_LEN: usize = 32;
const SHA2_384_KEY_LEN: usize = 48;
const SHA2_512_KEY_LEN: usize = 64;
const SHA2_512_224_KEY_LEN: usize = 64;
const SHA2_512_256_KEY_LEN: usize = 64;
const SHA3_256_KEY_LEN: usize = 32;
const SHA3_224_KEY_LEN: usize = 32;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize_repr, Deserialize_repr)]
#[repr(u8)]
pub enum Algorithm {
    // HMAC
    #[cfg(feature = "hmac_sha2")]
    Sha2_256 = 0,
    #[cfg(feature = "hmac_sha2")]
    Sha2_224 = 1,
    #[cfg(feature = "hmac_sha2")]
    Sha2_384 = 2,
    #[cfg(feature = "hmac_sha2")]
    Sha2_512 = 3,
    #[cfg(feature = "hmac_sha2")]
    Sha2_512_224 = 4,
    #[cfg(feature = "hmac_sha2")]
    Sha2_512_256 = 5,
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
    pub fn default_key_len(&self) -> usize {
        match self {
            #[cfg(feature = "hmac_sha2")]
            Algorithm::Sha2_256 => 32,
            #[cfg(feature = "hmac_sha2")]
            Algorithm::Sha2_224 => 32,
            #[cfg(feature = "hmac_sha2")]
            Algorithm::Sha2_384 => 48,
            #[cfg(feature = "hmac_sha2")]
            Algorithm::Sha2_512 => 64,
            #[cfg(feature = "hmac_sha2")]
            Algorithm::Sha2_512_224 => 64,
            #[cfg(feature = "hmac_sha2")]
            Algorithm::Sha2_512_256 => 64,
            #[cfg(feature = "hmac_sha3")]
            Algorithm::Sha3_256 => 32,
            #[cfg(feature = "hmac_sha3")]
            Algorithm::Sha3_224 => 32,
            #[cfg(feature = "hmac_sha3")]
            Algorithm::Sha3_384 => 64,
            #[cfg(feature = "hmac_sha3")]
            Algorithm::Sha3_512 => 64,
            #[cfg(feature = "blake3")]
            Algorithm::Blake3 => 64,
            #[cfg(feature = "cmac_aes")]
            Algorithm::Aes128 => 16,
            #[cfg(feature = "cmac_aes")]
            Algorithm::Aes192 => 24,
            #[cfg(feature = "cmac_aes")]
            Algorithm::Aes256 => 32,
        }
    }
}
