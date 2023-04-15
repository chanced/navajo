use alloc::vec;

use crate::Rng;

use super::{
    prk::{PrkInner, RustCryptoPrk},
    Algorithm, Prk,
};
/// A salt for HKDF.
#[derive(Clone)]
pub struct Salt {
    inner: SaltInner,
    algorithm: Algorithm,
}
impl Salt {
    pub fn new(algorithm: Algorithm, value: &[u8]) -> Self {
        let inner = match algorithm {
            Algorithm::Sha256 | Algorithm::Sha384 | Algorithm::Sha512 => {
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

    pub fn generate(algorithm: Algorithm) -> Self {
        Self::gen(&crate::SystemRng, algorithm)
    }
    #[cfg(test)]
    pub fn generate_with_rng<R>(rng: &R, algorithm: Algorithm) -> Self
    where
        R: crate::Rng,
    {
        Self::gen(rng, algorithm)
    }

    pub fn algorithm(&self) -> Algorithm {
        self.algorithm
    }
    pub fn extract(&self, secret: &[u8]) -> Prk {
        match &self.inner {
            #[cfg(feature = "ring")]
            SaltInner::Ring(ring) => ring.extract(secret),
            SaltInner::RustCrypto(rust_crypto) => rust_crypto.extract(secret),
        }
    }
    fn gen(rng: &impl Rng, algorithm: Algorithm) -> Salt {
        let mut salt = vec![0u8; algorithm.output_len()];
        rng.fill(&mut salt).unwrap();
        Salt::new(algorithm, &salt)
    }
}

#[allow(clippy::large_enum_variant)]
#[derive(Clone)]
enum SaltInner {
    #[cfg(feature = "ring")]
    Ring(RingSalt),
    RustCrypto(RustCryptoSalt),
}
#[derive(Clone)]
#[cfg(feature = "ring")]
struct RingSalt {
    salt: Arc<ring::hkdf::Salt>,
    // algorithm: Algorithm,
}
#[cfg(feature = "ring")]
impl RingSalt {
    fn new(algorithm: Algorithm, value: &[u8]) -> Self {
        Self {
            salt: Arc::new(ring::hkdf::Salt::new(algorithm.into(), value)),
            // algorithm,
        }
    }
    fn extract(&self, secret: &[u8]) -> Prk {
        let prk = self.salt.extract(secret);
        Prk {
            inner: PrkInner::Ring(prk),
        }
    }
}

#[derive(Clone)]
enum RustCryptoSalt {
    #[cfg(all(not(feature = "ring"), feature = "sha2", feature = "hmac"))]
    Sha256(hmac::Hmac<sha2::Sha256>),
    #[cfg(all(not(feature = "ring"), feature = "sha2", feature = "hmac"))]
    Sha384(hmac::Hmac<sha2::Sha384>),
    #[cfg(all(not(feature = "ring"), feature = "sha2", feature = "hmac"))]
    Sha512(hmac::Hmac<sha2::Sha512>),
    #[cfg(all(feature = "sha3", feature = "hmac"))]
    Sha3_256(hmac::Hmac<sha3::Sha3_256>),
    #[cfg(all(feature = "sha3", feature = "hmac"))]
    Sha3_224(hmac::Hmac<sha3::Sha3_224>),
    #[cfg(all(feature = "sha3", feature = "hmac"))]
    Sha3_384(hmac::Hmac<sha3::Sha3_384>),
    #[cfg(all(feature = "sha3", feature = "hmac"))]
    Sha3_512(hmac::Hmac<sha3::Sha3_512>),
}

impl RustCryptoSalt {
    // #[cfg(any(
    //     feature = "ring",
    //     all(feature = "sha2", feature = "hmac"),
    //     all(feature = "sha3", feature = "hmac")
    // ))]
    fn new(algorithm: Algorithm, value: &[u8]) -> Self {
        match algorithm {
            #[cfg(all(not(feature = "ring"), feature = "sha2", feature = "hmac"))]
            Algorithm::Sha256 => Self::Sha256(hmac::Mac::new_from_slice(value).unwrap()),
            #[cfg(all(not(feature = "ring"), feature = "sha2", feature = "hmac"))]
            Algorithm::Sha384 => Self::Sha384(hmac::Mac::new_from_slice(value).unwrap()),
            #[cfg(all(not(feature = "ring"), feature = "sha2", feature = "hmac"))]
            Algorithm::Sha512 => Self::Sha512(hmac::Mac::new_from_slice(value).unwrap()),
            #[cfg(feature = "sha3")]
            Algorithm::Sha3_256 => Self::Sha3_256(hmac::Mac::new_from_slice(value).unwrap()),
            #[cfg(feature = "sha3")]
            Algorithm::Sha3_224 => Self::Sha3_224(hmac::Mac::new_from_slice(value).unwrap()),
            #[cfg(feature = "sha3")]
            Algorithm::Sha3_384 => Self::Sha3_384(hmac::Mac::new_from_slice(value).unwrap()),
            #[cfg(feature = "sha3")]
            Algorithm::Sha3_512 => Self::Sha3_512(hmac::Mac::new_from_slice(value).unwrap()),
            #[cfg(feature = "ring")]
            _ => unreachable!("ring supports Sha256, Sha384, and Sha512"),
        }
    }
    fn extract(&self, secret: &[u8]) -> Prk {
        use hmac::Mac;
        match self {
            #[cfg(not(feature = "ring"))]
            RustCryptoSalt::Sha256(salt) => {
                let mut salt = salt.clone();
                salt.update(secret);
                Prk {
                    inner: PrkInner::RustCrypto(RustCryptoPrk::Sha256(
                        salt.finalize().into_bytes(),
                    )),
                }
            }
            #[cfg(not(feature = "ring"))]
            RustCryptoSalt::Sha384(salt) => {
                let mut salt = salt.clone();
                salt.update(secret);
                Prk {
                    inner: PrkInner::RustCrypto(RustCryptoPrk::Sha384(
                        salt.finalize().into_bytes(),
                    )),
                }
            }
            #[cfg(not(feature = "ring"))]
            RustCryptoSalt::Sha512(salt) => {
                let mut salt = salt.clone();
                salt.update(secret);
                Prk {
                    inner: PrkInner::RustCrypto(RustCryptoPrk::Sha512(
                        salt.finalize().into_bytes(),
                    )),
                }
            }
            #[cfg(feature = "sha3")]
            RustCryptoSalt::Sha3_256(salt) => {
                let mut salt = salt.clone();
                salt.update(secret);
                Prk {
                    inner: PrkInner::RustCrypto(RustCryptoPrk::Sha3_256(
                        salt.finalize().into_bytes(),
                    )),
                }
            }
            #[cfg(feature = "sha3")]
            RustCryptoSalt::Sha3_224(salt) => {
                let mut salt = salt.clone();
                salt.update(secret);
                Prk {
                    inner: PrkInner::RustCrypto(RustCryptoPrk::Sha3_224(
                        salt.finalize().into_bytes(),
                    )),
                }
            }
            #[cfg(feature = "sha3")]
            RustCryptoSalt::Sha3_384(salt) => {
                let mut salt = salt.clone();
                salt.update(secret);
                Prk {
                    inner: PrkInner::RustCrypto(RustCryptoPrk::Sha3_384(
                        salt.finalize().into_bytes(),
                    )),
                }
            }
            #[cfg(feature = "sha3")]
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
