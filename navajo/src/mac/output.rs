use core::{fmt::Debug, ops::Deref};

use alloc::vec::Vec;

pub(super) trait DigestOutput: AsRef<[u8]> + Clone {
    fn into_bytes(self) -> Vec<u8> {
        self.as_ref().to_vec()
    }
    fn truncatable(&self) -> bool;
}

#[derive(Clone, Debug)]
pub(super) enum Output {
    #[cfg(feature = "ring")]
    Ring(RingOutput),
    RustCrypto(RustCryptoOutput),
    #[cfg(feature = "blake3")]
    Blake3(Blake3Output),
}

impl Output {
    pub(super) fn as_bytes(&self) -> &[u8] {
        match self {
            #[cfg(feature = "ring")]
            Self::Ring(output) => output.as_ref(),
            Self::RustCrypto(output) => output.as_ref(),
            #[cfg(feature = "blake3")]
            Self::Blake3(output) => output.as_ref(),
        }
    }
}

impl DigestOutput for Output {
    fn truncatable(&self) -> bool {
        match self {
            #[cfg(feature = "ring")]
            Self::Ring(output) => output.truncatable(),
            Self::RustCrypto(output) => output.truncatable(),
            #[cfg(feature = "blake3")]
            Self::Blake3(output) => output.truncatable(),
        }
    }
}

impl AsRef<[u8]> for Output {
    fn as_ref(&self) -> &[u8] {
        self.as_bytes()
    }
}

#[cfg(all(feature = "ring", feature = "sha2"))]
#[derive(Clone, Debug)]
pub(super) struct RingOutput(ring::hmac::Tag);
#[cfg(all(feature = "ring", feature = "sha2"))]
impl AsRef<[u8]> for RingOutput {
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}
#[cfg(all(feature = "ring", feature = "sha2"))]
impl DigestOutput for RingOutput {
    fn truncatable(&self) -> bool {
        true
    }
}
#[cfg(all(feature = "ring", feature = "sha2"))]
impl From<ring::hmac::Tag> for Output {
    fn from(output: ring::hmac::Tag) -> Self {
        Self::Ring(RingOutput(output))
    }
}

#[cfg(feature = "blake3")]
#[derive(Clone, Debug)]
pub(super) struct Blake3Output(blake3::Hash);

#[cfg(feature = "blake3")]
impl DigestOutput for Blake3Output {
    fn truncatable(&self) -> bool {
        true
    } //github.com/BLAKE3-team/BLAKE3/issues/123
}
#[cfg(feature = "blake3")]
impl From<blake3::Hash> for Blake3Output {
    fn from(hash: blake3::Hash) -> Self {
        Self(hash)
    }
}
#[cfg(feature = "blake3")]
impl AsRef<[u8]> for Blake3Output {
    fn as_ref(&self) -> &[u8] {
        self.0.as_bytes()
    }
}
#[cfg(feature = "blake3")]
impl From<Blake3Output> for Output {
    fn from(output: Blake3Output) -> Self {
        Self::Blake3(output)
    }
}

#[derive(Clone, Debug)]
pub(super) enum RustCryptoOutput {
    #[cfg(all(not(feature = "ring"), feature = "sha2", feature = "hmac"))]
    Sha256(sha2::digest::Output<sha2::Sha256>),

    #[cfg(all(not(feature = "ring"), feature = "sha2", feature = "hmac"))]
    Sha384(sha2::digest::Output<sha2::Sha384>),

    #[cfg(all(not(feature = "ring"), feature = "sha2", feature = "hmac"))]
    Sha512(sha2::digest::Output<sha2::Sha512>),

    #[cfg(all(feature = "sha3", feature = "hmac"))]
    Sha3_256(sha3::digest::Output<sha3::Sha3_256>),

    #[cfg(all(feature = "sha3", feature = "hmac"))]
    Sha3_224(sha3::digest::Output<sha3::Sha3_224>),

    #[cfg(all(feature = "sha3", feature = "hmac"))]
    Sha3_384(sha3::digest::Output<sha3::Sha3_384>),

    #[cfg(all(feature = "sha3", feature = "hmac"))]
    Sha3_512(sha3::digest::Output<sha3::Sha3_512>),

    #[cfg(all(feature = "aes", feature = "cmac"))]
    Aes128(cmac::digest::Output<cmac::Cmac<aes::Aes128>>),

    #[cfg(all(feature = "aes", feature = "cmac"))]
    Aes192(cmac::digest::Output<cmac::Cmac<aes::Aes192>>),

    #[cfg(all(feature = "aes", feature = "cmac"))]
    Aes256(cmac::digest::Output<cmac::Cmac<aes::Aes256>>),
}
impl RustCryptoOutput {
    fn truncatable(&self) -> bool {
        // todo: handle this if new algorithms are added
        true
    }
}
impl AsRef<[u8]> for RustCryptoOutput {
    fn as_ref(&self) -> &[u8] {
        match self {
            #[cfg(all(not(feature = "ring"), feature = "sha2", feature = "hmac"))]
            Self::Sha256(output) => output.as_ref(),
            #[cfg(all(not(feature = "ring"), feature = "sha2", feature = "hmac"))]
            Self::Sha384(output) => output.as_ref(),
            #[cfg(all(not(feature = "ring"), feature = "sha2", feature = "hmac"))]
            Self::Sha512(output) => output.as_ref(),
            #[cfg(all(feature = "sha3", feature = "hmac"))]
            Self::Sha3_256(output) => output.as_ref(),
            #[cfg(all(feature = "sha3", feature = "hmac"))]
            Self::Sha3_224(output) => output.as_ref(),
            #[cfg(all(feature = "sha3", feature = "hmac"))]
            Self::Sha3_384(output) => output.as_ref(),
            #[cfg(all(feature = "sha3", feature = "hmac"))]
            Self::Sha3_512(output) => output.as_ref(),
            #[cfg(all(feature = "aes", feature = "cmac"))]
            Self::Aes128(output) => output.as_ref(),
            #[cfg(all(feature = "aes", feature = "cmac"))]
            Self::Aes192(output) => output.as_ref(),
            #[cfg(all(feature = "aes", feature = "cmac"))]
            Self::Aes256(output) => output.as_ref(),
        }
    }
}
impl Deref for RustCryptoOutput {
    type Target = [u8];
    fn deref(&self) -> &Self::Target {
        match self {
            #[cfg(all(not(feature = "ring"), feature = "sha2", feature = "hmac"))]
            Self::Sha256(output) => output.as_ref(),
            #[cfg(all(not(feature = "ring"), feature = "sha2", feature = "hmac"))]
            Self::Sha384(output) => output.as_ref(),
            #[cfg(all(not(feature = "ring"), feature = "sha2", feature = "hmac"))]
            Self::Sha512(output) => output.as_ref(),
            #[cfg(all(feature = "sha3", feature = "hmac"))]
            Self::Sha3_256(output) => output.as_ref(),
            #[cfg(all(feature = "sha3", feature = "hmac"))]
            Self::Sha3_224(output) => output.as_ref(),
            #[cfg(all(feature = "sha3", feature = "hmac"))]
            Self::Sha3_384(output) => output.as_ref(),
            #[cfg(all(feature = "sha3", feature = "hmac"))]
            Self::Sha3_512(output) => output.as_ref(),
            #[cfg(all(feature = "aes", feature = "cmac"))]
            Self::Aes128(output) => output.as_ref(),
            #[cfg(all(feature = "aes", feature = "cmac"))]
            Self::Aes192(output) => output.as_ref(),
            #[cfg(all(feature = "aes", feature = "cmac"))]
            Self::Aes256(output) => output.as_ref(),
        }
    }
}
