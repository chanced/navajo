use serde_repr::{Deserialize_repr, Serialize_repr};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize_repr, Deserialize_repr)]
#[repr(u8)]
pub enum Algorithm {
    // HMAC
    Sha256 = 0,
    Sha512 = 1,
    Sha224 = 2,
    Sha384 = 3,
    Sha3_256 = 4,
    Sha3_512 = 5,
    Sha3_224 = 6,
    Sha3_384 = 7,
    // leaving room for other hmac algorithms such as blake3
    // CMAC
    Aes128 = 128,
    Aes192 = 129,
    Aes256 = 130,
}
