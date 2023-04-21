use crate::{key::Key, mac::output};
use alloc::vec::Vec;

use super::{
    entry::Entry,
    material::{BackendKey, Material, RustCryptoKey},
    output::{RustCryptoOutput},
};

pub(super) struct Context {
    is_primary: bool,
    inner: Inner,
    header: Vec<u8>,
}
impl Context {
    pub(super) fn new(key: &Key<Material>) -> Self {
        Self {
            is_primary: key.is_primary(),
            inner: Inner::new(key.new_backend_key()),
            header: key.header(),
        }
    }
    pub(super) fn update(&mut self, data: &[u8]) {
        self.inner.update(data)
    }
    // pub(super) fn is_primary(&self) -> bool {
    //     self.is_primary
    // }
    // pub(super) fn key_id(&self) -> u32 {
    //     self.key_id
    // }

    pub(super) fn finalize(self) -> Entry {
        Entry::new(self.is_primary, self.header, self.inner.finalize())
    }
}
#[allow(clippy::large_enum_variant)]
enum Inner {
    #[cfg(feature = "blake3")]
    Blake3(Blake3Context),
    #[cfg(feature = "ring")]
    Ring(RingContext),
    RustCrypto(RustCryptoContext),
}

#[cfg(feature = "ring")]
impl From<ring::hmac::Key> for Inner {
    fn from(key: ring::hmac::Key) -> Self {
        Self::Ring(key.into())
    }
}

#[cfg(feature = "blake3")]
impl From<blake3::Hasher> for Inner {
    fn from(hasher: blake3::Hasher) -> Self {
        Self::Blake3(Blake3Context(hasher))
    }
}

impl From<RustCryptoKey> for Inner {
    fn from(key: RustCryptoKey) -> Self {
        Self::RustCrypto(RustCryptoContext(key))
    }
}

impl Inner {
    pub(super) fn new(key: BackendKey) -> Inner {
        match key {
            #[cfg(feature = "ring")]
            BackendKey::Ring(key) => key.into(),
            BackendKey::RustCrypto(key) => key.into(),
            #[cfg(feature = "blake3")]
            BackendKey::Blake3(key) => key.into(),
        }
    }
    pub(super) fn update(&mut self, data: &[u8]) {
        match self {
            #[cfg(feature = "blake3")]
            Self::Blake3(ctx) => ctx.update(data),
            #[cfg(feature = "ring")]
            Self::Ring(ctx) => ctx.update(data),
            Self::RustCrypto(ctx) => ctx.update(data),
        }
    }
    pub(super) fn finalize(self) -> output::Output {
        match self {
            #[cfg(feature = "blake3")]
            Self::Blake3(ctx) => ctx.finalize(),
            #[cfg(feature = "ring")]
            Self::Ring(ctx) => ctx.finalize(),
            Self::RustCrypto(ctx) => ctx.finalize(),
        }
    }
}

#[cfg(feature = "blake3")]
#[derive(Clone)]
pub(crate) struct Blake3Context(blake3::Hasher);

#[cfg(feature = "blake3")]
impl Blake3Context {
    fn update(&mut self, data: &[u8]) {
        self.0.update(data);
    }
    fn finalize(self) -> output::Output {
        output::Output::Blake3(self.0.finalize().into())
    }
}
#[cfg(feature = "blake3")]
impl From<blake3::Hasher> for Blake3Context {
    fn from(hasher: blake3::Hasher) -> Self {
        Self(hasher)
    }
}

#[cfg(feature = "ring")]
pub(super) struct RingContext(ring::hmac::Context);

#[cfg(feature = "ring")]
impl RingContext {
    fn update(&mut self, data: &[u8]) {
        self.0.update(data);
    }
    fn finalize(self) -> Output {
        self.0.sign().into()
    }
}

#[cfg(all(feature = "ring"))]
impl From<ring::hmac::Key> for RingContext {
    fn from(key: ring::hmac::Key) -> Self {
        Self(ring::hmac::Context::with_key(&key))
    }
}

struct RustCryptoContext(RustCryptoKey);
impl RustCryptoContext {
    fn update(&mut self, data: &[u8]) {
        match self.0 {
            #[cfg(all(not(feature = "ring"), feature = "sha2", feature = "hmac"))]
            RustCryptoKey::Sha256(ref mut k) => hmac::Mac::update(k, data),
            #[cfg(all(not(feature = "ring"), feature = "sha2", feature = "hmac"))]
            RustCryptoKey::Sha384(ref mut k) => hmac::Mac::update(k, data),
            #[cfg(all(not(feature = "ring"), feature = "sha2", feature = "hmac"))]
            RustCryptoKey::Sha512(ref mut k) => hmac::Mac::update(k, data),
            #[cfg(all(feature = "sha3", feature = "hmac"))]
            RustCryptoKey::Sha3_256(ref mut k) => hmac::Mac::update(k, data),
            #[cfg(all(feature = "sha3", feature = "hmac"))]
            RustCryptoKey::Sha3_224(ref mut k) => hmac::Mac::update(k, data),
            #[cfg(all(feature = "sha3", feature = "hmac"))]
            RustCryptoKey::Sha3_384(ref mut k) => hmac::Mac::update(k, data),
            #[cfg(all(feature = "sha3", feature = "hmac"))]
            RustCryptoKey::Sha3_512(ref mut k) => hmac::Mac::update(k, data),
            #[cfg(all(feature = "aes", feature = "cmac"))]
            RustCryptoKey::Aes128(ref mut k) => cmac::Mac::update(k, data),
            #[cfg(all(feature = "aes", feature = "cmac"))]
            RustCryptoKey::Aes192(ref mut k) => cmac::Mac::update(k, data),
            #[cfg(all(feature = "aes", feature = "cmac"))]
            RustCryptoKey::Aes256(ref mut k) => cmac::Mac::update(k, data),
        }
    }
    fn finalize(self) -> output::Output {
        let output = match self.0 {
            #[cfg(all(not(feature = "ring"), feature = "sha2", feature = "hmac"))]
            RustCryptoKey::Sha256(k) => {
                RustCryptoOutput::Sha256(hmac::Mac::finalize(k).into_bytes())
            }
            #[cfg(all(not(feature = "ring"), feature = "sha2", feature = "hmac"))]
            RustCryptoKey::Sha384(k) => {
                RustCryptoOutput::Sha384(hmac::Mac::finalize(k).into_bytes())
            }
            #[cfg(all(not(feature = "ring"), feature = "sha2", feature = "hmac"))]
            RustCryptoKey::Sha512(k) => {
                RustCryptoOutput::Sha512(hmac::Mac::finalize(k).into_bytes())
            }
            #[cfg(all(feature = "sha3", feature = "hmac"))]
            RustCryptoKey::Sha3_256(k) => {
                RustCryptoOutput::Sha3_256(hmac::Mac::finalize(k).into_bytes())
            }
            #[cfg(all(feature = "sha3", feature = "hmac"))]
            RustCryptoKey::Sha3_224(k) => {
                RustCryptoOutput::Sha3_224(hmac::Mac::finalize(k).into_bytes())
            }
            #[cfg(all(feature = "sha3", feature = "hmac"))]
            RustCryptoKey::Sha3_384(k) => {
                RustCryptoOutput::Sha3_384(hmac::Mac::finalize(k).into_bytes())
            }
            #[cfg(all(feature = "sha3", feature = "hmac"))]
            RustCryptoKey::Sha3_512(k) => {
                RustCryptoOutput::Sha3_512(hmac::Mac::finalize(k).into_bytes())
            }
            #[cfg(all(feature = "aes", feature = "cmac"))]
            RustCryptoKey::Aes128(k) => {
                RustCryptoOutput::Aes128(cmac::Mac::finalize(k).into_bytes())
            }
            #[cfg(all(feature = "aes", feature = "cmac"))]
            RustCryptoKey::Aes192(k) => {
                RustCryptoOutput::Aes192(cmac::Mac::finalize(k).into_bytes())
            }
            #[cfg(all(feature = "aes", feature = "cmac"))]
            RustCryptoKey::Aes256(k) => {
                RustCryptoOutput::Aes256(cmac::Mac::finalize(k).into_bytes())
            }
        };
        output::Output::RustCrypto(output)
    }
}
