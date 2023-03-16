use crate::error::InvalidLengthError;

/// Psuedo-random key
#[derive(Clone, Debug)]
pub struct Prk {
    pub(super) inner: PrkInner,
}

#[cfg(any(
    feature = "ring",
    all(feature = "sha2", feature = "hmac"),
    all(feature = "sha3", feature = "hmac")
))]
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
    #[cfg(all(not(feature = "ring"), feature = "sha2", feature = "hmac"))]
    Sha256(hmac::digest::Output<hmac::Hmac<sha2::Sha256>>),
    #[cfg(all(not(feature = "ring"), feature = "sha2", feature = "hmac"))]
    Sha384(hmac::digest::Output<hmac::Hmac<sha2::Sha384>>),
    #[cfg(all(not(feature = "ring"), feature = "sha2", feature = "hmac"))]
    Sha512(hmac::digest::Output<hmac::Hmac<sha2::Sha512>>),
    #[cfg(all(feature = "sha3", feature = "hmac"))]
    Sha3_256(hmac::digest::Output<hmac::Hmac<sha3::Sha3_256>>),
    #[cfg(all(feature = "sha3", feature = "hmac"))]
    Sha3_224(hmac::digest::Output<hmac::Hmac<sha3::Sha3_224>>),
    #[cfg(all(feature = "sha3", feature = "hmac"))]
    Sha3_384(hmac::digest::Output<hmac::Hmac<sha3::Sha3_384>>),
    #[cfg(all(feature = "sha3", feature = "hmac"))]
    Sha3_512(hmac::digest::Output<hmac::Hmac<sha3::Sha3_512>>),
}
impl RustCryptoPrk {
    fn expand(&self, info: &[&[u8]], out: &mut [u8]) -> Result<(), InvalidLengthError> {
        use rust_crypto_hkdf::Hkdf;
        match self {
            #[cfg(all(not(feature = "ring"), feature = "sha2", feature = "hmac"))]
            RustCryptoPrk::Sha256(prk) => {
                let hk = Hkdf::<sha2::Sha256>::from_prk(prk).unwrap();
                hk.expand_multi_info(info, out)?;
            }
            #[cfg(all(not(feature = "ring"), feature = "sha2", feature = "hmac"))]
            RustCryptoPrk::Sha384(prk) => {
                let hk = Hkdf::<sha2::Sha384>::from_prk(prk).unwrap();
                hk.expand_multi_info(info, out)?;
            }
            #[cfg(all(not(feature = "ring"), feature = "sha2", feature = "hmac"))]
            RustCryptoPrk::Sha512(prk) => {
                let hk = Hkdf::<sha2::Sha512>::from_prk(prk).unwrap();
                hk.expand_multi_info(info, out)?;
            }
            #[cfg(feature = "sha3")]
            RustCryptoPrk::Sha3_256(prk) => {
                let hk = Hkdf::<sha3::Sha3_256>::from_prk(prk).unwrap();
                hk.expand_multi_info(info, out)?;
            }
            #[cfg(feature = "sha3")]
            RustCryptoPrk::Sha3_224(prk) => {
                let hk = Hkdf::<sha3::Sha3_224>::from_prk(prk).unwrap();
                hk.expand_multi_info(info, out)?;
            }
            #[cfg(feature = "sha3")]
            RustCryptoPrk::Sha3_384(prk) => {
                let hk = Hkdf::<sha3::Sha3_384>::from_prk(prk).unwrap();
                hk.expand_multi_info(info, out)?;
            }
            #[cfg(feature = "sha3")]
            RustCryptoPrk::Sha3_512(prk) => {
                let hk = Hkdf::<sha3::Sha3_512>::from_prk(prk).unwrap();
                hk.expand_multi_info(info, out)?;
            }
        };
        Ok(())
    }

    // #[cfg(any(
    //     feature = "ring",
    //     all(feature = "sha2", feature = "hmac"),
    //     all(feature = "sha3", feature = "hmac")
    // ))]
    // fn algorithm(&self) -> Algorithm {
    //     match self {
    //         #[cfg(all(not(feature = "ring"), feature = "sha2", feature = "hmac"))]
    //         RustCryptoPrk::Sha256(_) => Algorithm::Sha256,
    //         #[cfg(all(not(feature = "ring"), feature = "sha2", feature = "hmac"))]
    //         RustCryptoPrk::Sha384(_) => Algorithm::Sha384,
    //         #[cfg(all(not(feature = "ring"), feature = "sha2", feature = "hmac"))]
    //         RustCryptoPrk::Sha512(_) => Algorithm::Sha512,
    //         #[cfg(all(feature = "sha3", feature = "hmac"))]
    //         RustCryptoPrk::Sha3_256(_) => Algorithm::Sha256,
    //         #[cfg(all(feature = "sha3", feature = "hmac"))]
    //         RustCryptoPrk::Sha3_224(_) => Algorithm::Sha3_224,
    //         #[cfg(all(feature = "sha3", feature = "hmac"))]
    //         RustCryptoPrk::Sha3_384(_) => Algorithm::Sha3_384,
    //         #[cfg(all(feature = "sha3", feature = "hmac"))]
    //         RustCryptoPrk::Sha3_512(_) => Algorithm::Sha3_512,
    //     }
    // }
}
