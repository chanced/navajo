use super::{
    prk::{PrkInner, RustCryptoPrk},
    Algorithm, Prk,
};
/// A salt for HKDF.
pub struct Salt {
    inner: SaltInner,
    algorithm: Algorithm,
}
impl Salt {
    pub fn new(algorithm: Algorithm, value: &[u8]) -> Self {
        let inner = match algorithm {
            Algorithm::HkdfSha256 | Algorithm::HkdfSha384 | Algorithm::HkdfSha512 => {
                #[cfg(feature = "ring")]
                {
                    SaltInner::Ring(RingSalt::new(algorithm, value))
                }
                #[cfg(not(feature = "ring"))]
                {
                    SaltInner::RustCrypto(RustCryptoSalt::new(algorithm, value))
                }
            }
            _ => SaltInner::RustCrypto(RustCryptoSalt::new(algorithm, value)),
        };
        Self { inner, algorithm }
    }
    pub fn algorithm(&self) -> Algorithm {
        self.algorithm
    }
    pub fn extract(&self, secret: &[u8]) -> Prk {
        match &self.inner {
            SaltInner::Ring(ring) => ring.extract(secret),
            SaltInner::RustCrypto(rust_crypto) => rust_crypto.extract(secret),
        }
    }
}

#[allow(clippy::large_enum_variant)]
enum SaltInner {
    #[cfg(feature = "ring")]
    Ring(RingSalt),
    RustCrypto(RustCryptoSalt),
}

struct RingSalt {
    salt: ring::hkdf::Salt,
    algorithm: Algorithm,
}
impl RingSalt {
    fn new(algorithm: Algorithm, value: &[u8]) -> Self {
        Self {
            salt: ring::hkdf::Salt::new(algorithm.into(), value),
            algorithm,
        }
    }
    fn extract(&self, secret: &[u8]) -> Prk {
        let prk = self.salt.extract(secret);
        Prk {
            inner: PrkInner::Ring(prk),
        }
    }
}

enum RustCryptoSalt {
    #[cfg(not(feature = "ring"))]
    Sha256(hmac::Hmac<sha2::Sha256>),
    #[cfg(not(feature = "ring"))]
    Sha384(hmac::Hmac<sha2::Sha384>),
    #[cfg(not(feature = "ring"))]
    Sha512(hmac::Hmac<sha2::Sha512>),
    Sha224(hmac::Hmac<sha2::Sha224>),
    Sha512_224(hmac::Hmac<sha2::Sha512_224>),
    Sha512_256(hmac::Hmac<sha2::Sha512_256>),
    Sha3_256(hmac::Hmac<sha3::Sha3_256>),
    Sha3_224(hmac::Hmac<sha3::Sha3_224>),
    Sha3_384(hmac::Hmac<sha3::Sha3_384>),
    Sha3_512(hmac::Hmac<sha3::Sha3_512>),
}

impl RustCryptoSalt {
    fn new(algorithm: Algorithm, value: &[u8]) -> Self {
        use hmac::Mac;
        match algorithm {
            #[cfg(not(feature = "ring"))]
            Algorithm::HkdfSha256 => Self::Sha256(hmac::Hmac::new_from_slice(value).unwrap()),
            #[cfg(not(feature = "ring"))]
            Algorithm::HkdfSha384 => Self::Sha224(RustCryptoSaltInner {
                hmac: hmac::Hmac::new_from_slice(&value).unwrap(),
                algorithm,
            }),
            #[cfg(not(feature = "ring"))]
            Algorithm::HkdfSha512 => Self::Sha512(RustCryptoSaltInner {
                hmac: hmac::Hmac::new_from_slice(value).unwrap(),
                algorithm,
            }),
            Algorithm::HkdfSha224 => Self::Sha224(hmac::Hmac::new_from_slice(value).unwrap()),
            Algorithm::HkdfSha512_224 => {
                Self::Sha512_224(hmac::Hmac::new_from_slice(value).unwrap())
            }
            Algorithm::HkdfSha512_256 => {
                Self::Sha512_256(hmac::Hmac::new_from_slice(value).unwrap())
            }
            Algorithm::HkdfSha3_256 => Self::Sha3_256(hmac::Hmac::new_from_slice(value).unwrap()),
            Algorithm::HkdfSha3_224 => Self::Sha3_224(hmac::Hmac::new_from_slice(value).unwrap()),
            Algorithm::HkdfSha3_384 => Self::Sha3_384(hmac::Hmac::new_from_slice(value).unwrap()),
            Algorithm::HkdfSha3_512 => Self::Sha3_512(hmac::Hmac::new_from_slice(value).unwrap()),

            _ => unreachable!("ring supports Sha256, Sha384, and Sha512"),
        }
    }
    fn extract(&self, secret: &[u8]) -> Prk {
        use hmac::Mac;
        match self {
            #[cfg(not(feature = "ring"))]
            RustCryptoSalt::Sha256(mut salt) => {
                let mut salt = salt.clone();
                salt.update(secret);
                Prk {
                    inner: PrkInner::RustCrypto(RustCryptoPrk::Sha256(
                        salt.finalize().into_bytes(),
                    )),
                }
            }
            #[cfg(not(feature = "ring"))]
            RustCryptoSalt::Sha384(mut salt) => {
                let mut salt = salt.clone();
                salt.update(secret);
                Prk {
                    inner: PrkInner::RustCrypto(RustCryptoPrk::Sha384(
                        salt.finalize().into_bytes(),
                    )),
                }
            }
            #[cfg(not(feature = "ring"))]
            RustCryptoSalt::Sha512(mut salt) => {
                let mut salt = salt.clone();
                salt.update(secret);
                Prk {
                    inner: PrkInner::RustCrypto(RustCryptoPrk::Sha512(
                        salt.finalize().into_bytes(),
                    )),
                }
            }
            RustCryptoSalt::Sha224(salt) => {
                let mut salt = salt.clone();
                salt.update(secret);
                Prk {
                    inner: PrkInner::RustCrypto(RustCryptoPrk::Sha224(
                        salt.finalize().into_bytes(),
                    )),
                }
            }
            RustCryptoSalt::Sha512_224(salt) => {
                let mut salt = salt.clone();
                salt.update(secret);
                Prk {
                    inner: PrkInner::RustCrypto(RustCryptoPrk::Sha512_224(
                        salt.finalize().into_bytes(),
                    )),
                }
            }
            RustCryptoSalt::Sha512_256(salt) => {
                let mut salt = salt.clone();
                salt.update(secret);
                Prk {
                    inner: PrkInner::RustCrypto(RustCryptoPrk::Sha512_256(
                        salt.finalize().into_bytes(),
                    )),
                }
            }
            RustCryptoSalt::Sha3_256(salt) => {
                let mut salt = salt.clone();
                salt.update(secret);
                Prk {
                    inner: PrkInner::RustCrypto(RustCryptoPrk::Sha3_256(
                        salt.finalize().into_bytes(),
                    )),
                }
            }
            RustCryptoSalt::Sha3_224(salt) => {
                let mut salt = salt.clone();
                salt.update(secret);
                Prk {
                    inner: PrkInner::RustCrypto(RustCryptoPrk::Sha3_224(
                        salt.finalize().into_bytes(),
                    )),
                }
            }
            RustCryptoSalt::Sha3_384(salt) => {
                let mut salt = salt.clone();
                salt.update(secret);
                Prk {
                    inner: PrkInner::RustCrypto(RustCryptoPrk::Sha3_384(
                        salt.finalize().into_bytes(),
                    )),
                }
            }
            RustCryptoSalt::Sha3_512(salt) => {
                let mut salt = salt.clone();
                salt.update(secret);
                Prk {
                    inner: PrkInner::RustCrypto(RustCryptoPrk::Sha3_512(
                        salt.finalize().into_bytes(),
                    )),
                }
            }
        }
    }
}
