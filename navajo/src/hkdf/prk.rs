use crypto_common::OutputSizeUser;
use digest::{core_api::CoreWrapper, CtOutput};

use crate::error::InvalidLengthError;

use super::Algorithm;

/// Psuedo-random key
#[derive(Clone, Debug)]
pub struct Prk {
    pub(super) inner: PrkInner,
}

impl Prk {
    pub fn expand(&self, info: &[&[u8]], out: &mut [u8]) -> Result<(), InvalidLengthError> {
        match &self.inner {
            #[cfg(feature = "ring")]
            PrkInner::Ring(prk) => {
                let len = Length(out.len());
                let okm = prk.expand(info, len)?;
                okm.fill(out)?;
                Ok(())
            }
            PrkInner::RustCrypto(prk) => prk.expand(info, out),
        }
    }
}

struct Length(usize);
#[cfg(feature = "ring")]
impl ring::hkdf::KeyType for Length {
    fn len(&self) -> usize {
        self.0
    }
}

#[derive(Clone, Debug)]
pub(super) enum PrkInner {
    #[cfg(feature = "ring")]
    Ring(ring::hkdf::Prk),
    RustCrypto(RustCryptoPrk),
}
#[derive(Clone, Debug)]
pub(super) enum RustCryptoPrk {
    #[cfg(not(feature = "ring"))]
    Sha256(digest::Output<hmac::Hmac<sha2::Sha256>>),
    #[cfg(not(feature = "ring"))]
    Sha384(digest::Output<hmac::Hmac<sha2::Sha384>>),
    #[cfg(not(feature = "ring"))]
    Sha512(digest::Output<hmac::Hmac<sha2::Sha512>>),
    Sha224(digest::Output<hmac::Hmac<sha2::Sha224>>),
    Sha512_224(digest::Output<hmac::Hmac<sha2::Sha512_224>>),
    Sha512_256(digest::Output<hmac::Hmac<sha2::Sha512_256>>),
    Sha3_256(digest::Output<hmac::Hmac<sha3::Sha3_256>>),
    Sha3_224(digest::Output<hmac::Hmac<sha3::Sha3_224>>),
    Sha3_384(digest::Output<hmac::Hmac<sha3::Sha3_384>>),
    Sha3_512(digest::Output<hmac::Hmac<sha3::Sha3_512>>),
}
impl RustCryptoPrk {
    fn expand(&self, info: &[&[u8]], out: &mut [u8]) -> Result<(), InvalidLengthError> {
        use rust_crypto_hkdf::Hkdf;
        match self {
            #[cfg(not(feature = "ring"))]
            RustCryptoPrk::Sha256(prk) => {
                let hk = Hkdf::<sha2::Sha256>::from_prk(prk).unwrap();
                hk.expand_multi_info(info, out)?;
            }
            #[cfg(not(feature = "ring"))]
            RustCryptoPrk::Sha384(prk) => {
                let hk = Hkdf::<sha2::Sha384>::from_prk(prk).unwrap();
                hk.expand_multi_info(info, out)?;
            }
            #[cfg(not(feature = "ring"))]
            RustCryptoPrk::Sha512(prk) => {
                let hk = Hkdf::<sha2::Sha512>::from_prk(prk).unwrap();
                hk.expand_multi_info(info, out)?;
            }
            RustCryptoPrk::Sha224(prk) => {
                let hk = Hkdf::<sha2::Sha224>::from_prk(prk).unwrap();
                hk.expand_multi_info(info, out)?;
            }
            RustCryptoPrk::Sha512_224(prk) => {
                let hk = Hkdf::<sha2::Sha512_224>::from_prk(prk).unwrap();
                hk.expand_multi_info(info, out)?;
            }
            RustCryptoPrk::Sha512_256(prk) => {
                let hk = Hkdf::<sha2::Sha512_256>::from_prk(prk).unwrap();
                hk.expand_multi_info(info, out)?;
            }
            RustCryptoPrk::Sha3_256(prk) => {
                let hk = Hkdf::<sha3::Sha3_256>::from_prk(prk).unwrap();
                hk.expand_multi_info(info, out)?;
            }
            RustCryptoPrk::Sha3_224(prk) => {
                let hk = Hkdf::<sha3::Sha3_224>::from_prk(prk).unwrap();
                hk.expand_multi_info(info, out)?;
            }
            RustCryptoPrk::Sha3_384(prk) => {
                let hk = Hkdf::<sha3::Sha3_384>::from_prk(prk).unwrap();
                hk.expand_multi_info(info, out)?;
            }
            RustCryptoPrk::Sha3_512(prk) => {
                let hk = Hkdf::<sha3::Sha3_512>::from_prk(prk).unwrap();
                hk.expand_multi_info(info, out)?;
            }
        };
        Ok(())
    }
    fn algorithm(&self) -> Algorithm {
        match self {
            #[cfg(not(feature = "ring"))]
            RustCryptoPrk::Sha256(_) => Algorithm::HkdfSha256,
            #[cfg(not(feature = "ring"))]
            RustCryptoPrk::Sha384(_) => Algorithm::HkdfSha384,
            #[cfg(not(feature = "ring"))]
            RustCryptoPrk::Sha512(_) => Algorithm::HkdfSha512,
            RustCryptoPrk::Sha224(_) => Algorithm::HkdfSha224,
            RustCryptoPrk::Sha512_224(_) => Algorithm::HkdfSha512_224,
            RustCryptoPrk::Sha512_256(_) => Algorithm::HkdfSha512_256,
            RustCryptoPrk::Sha3_256(_) => Algorithm::HkdfSha256,
            RustCryptoPrk::Sha3_224(_) => Algorithm::HkdfSha3_224,
            RustCryptoPrk::Sha3_384(_) => Algorithm::HkdfSha3_384,
            RustCryptoPrk::Sha3_512(_) => Algorithm::HkdfSha3_512,
        }
    }
}
