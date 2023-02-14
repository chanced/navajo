use crate::{key::Key, mac::output};
use alloc::{boxed::Box, vec::Vec};

use super::{
    entry::Entry,
    material::{CryptoKey, Material},
    RustCryptoKey,
};

pub(super) struct Context {
    pub(super) key_id: u32,
    pub(super) is_primary: bool,
    pub(super) inner: ContextInner,
    pub(super) header: Vec<u8>,
}
impl Context {
    pub(super) fn new(key: &Key<Material>) -> Self {
        Self {
            key_id: key.id(),
            is_primary: key.is_primary(),
            inner: ContextInner::new(key.crypto_key()),
            header: key.header(),
        }
    }
    pub(super) fn update(&mut self, data: &[u8]) {
        self.inner.update(data)
    }
    pub(super) fn finalize(self) -> Entry {
        Entry::new(
            self.key_id,
            self.is_primary,
            self.header,
            self.inner.finalize(),
        )
    }
}

pub(super) enum ContextInner {
    #[cfg(feature = "blake3")]
    Blake3(crate::mac::Blake3Context),
    #[cfg(all(feature = "ring", feature = "hmac_sha2"))]
    Ring(crate::mac::RingContext),
    RustCrypto(crate::mac::RustCryptoContext),
}

#[cfg(all(feature = "ring", feature = "hmac_sha2"))]
impl From<Box<ring::hmac::Key>> for ContextInner {
    fn from(key: Box<ring::hmac::Key>) -> Self {
        Self::Ring(key.into())
    }
}

#[cfg(feature = "blake3")]
impl From<Box<blake3::Hasher>> for ContextInner {
    fn from(hasher: Box<blake3::Hasher>) -> Self {
        Self::Blake3(Blake3Context(hasher))
    }
}

impl From<Box<RustCryptoKey>> for ContextInner {
    fn from(key: Box<RustCryptoKey>) -> Self {
        Self::RustCrypto(key.into())
    }
}

impl ContextInner {
    pub(super) fn new(key: CryptoKey) -> ContextInner {
        match key {
            #[cfg(all(feature = "ring", feature = "hmac_sha2"))]
            CryptoKey::Ring(key) => key.into(),
            CryptoKey::RustCrypto(key) => key.into(),
            #[cfg(feature = "blake3")]
            CryptoKey::Blake3(key) => key.into(),
        }
    }
    pub(super) fn update(&mut self, data: &[u8]) {
        match self {
            #[cfg(feature = "blake3")]
            Self::Blake3(ctx) => ctx.update(data),
            #[cfg(all(feature = "ring", feature = "hmac_sha2"))]
            Self::Ring(ctx) => ctx.update(data),
            Self::RustCrypto(ctx) => ctx.update(data),
        }
    }
    pub(super) fn finalize(self) -> output::Output {
        match self {
            #[cfg(feature = "blake3")]
            Self::Blake3(ctx) => ctx.finalize(),
            #[cfg(all(feature = "ring", feature = "hmac_sha2"))]
            Self::Ring(ctx) => ctx.finalize(),
            Self::RustCrypto(ctx) => ctx.finalize(),
        }
    }
}

pub(super) trait MacContext {
    fn update(&mut self, data: &[u8]);
    fn finalize(self) -> output::Output;
}
#[cfg(feature = "blake3")]
#[derive(Clone)]
pub(crate) struct Blake3Context(Box<blake3::Hasher>);

impl From<Box<blake3::Hasher>> for Blake3Context {
    fn from(hasher: Box<blake3::Hasher>) -> Self {
        Self(hasher)
    }
}
impl MacContext for Blake3Context {
    fn update(&mut self, data: &[u8]) {
        self.0.update(data);
    }
    fn finalize(self) -> output::Output {
        output::Output::Blake3(self.0.finalize().into())
    }
}
cfg_if::cfg_if! {
    if #[cfg(all(feature = "ring", feature="hmac_sha2"))]{
        pub(super) struct RingContext(Box<ring::hmac::Context>);

        impl MacContext for RingContext {
            fn update(&mut self, data: &[u8]) {
                self.0.update(data);
            }
            fn finalize(self) -> Output {
                self.0.sign().into()
            }
        }
        impl From<Box<ring::hmac::Key>> for RingContext {
            fn from(key: Box<ring::hmac::Key>) -> Self {
                Self(Box::new(ring::hmac::Context::with_key(&key)))
            }
        }
    }
}

macro_rules! rust_crypto_context_inner {
    ($typ:ident, $crt:ident, $alg:ident, $feat:meta$(, not($cfg:meta))?) => {
        cfg_if::cfg_if! {
            if #[cfg(all($feat, $(not($cfg))?))] {
                paste::paste! {
                    #[derive(Clone, Debug)]
                    pub(super) struct [<$typ $alg Context>] (pub(crate) alloc::boxed::Box<[< $typ:lower >]::$typ<$crt::$alg>>);
                    impl MacContext for [<$typ $alg Context>] {
                        fn update(&mut self, data: &[u8]) {
                            use [< $typ:lower >]::Mac;
                            self.0.update(data);
                        }
                        fn finalize(self) -> Output {
                            use [< $typ:lower >]::Mac;
                            self.0.finalize().into()
                        }
                    }
                    impl From<[<$typ $alg Context>]> for RustCryptoContext {
                        fn from(ctx: [<$typ $alg Context>]) -> Self {
                            RustCryptoContext::$alg(ctx)
                        }
                    }
                    impl From<[< $typ:lower >]::$typ<$crt::$alg>> for [<$typ $alg Context>] {
                        fn from(ctx: [< $typ:lower >]::$typ<$crt::$alg>) -> Self {
                            Self(alloc::boxed::Box::new(ctx))
                        }
                    }
                }
            }
        }
    };
}
macro_rules! rust_crypto_contexts {
    ({
        hmac: { ring: [$($ring:ident),*], sha2: [$($sha2:ident),*], sha3: [$($sha3:ident),*]$(,)? },
        cmac: { aes: [$($aes:ident),*]$(,)? }
	}) => {
        paste::paste!{
        pub(crate) enum RustCryptoContext {
                $(
                    #[cfg(all(feature = "hmac_sha2", not(feature="ring")))]
                    $ring([< Hmac $ring Context>]),
                )*
                $(
                    #[cfg(feature = "hmac_sha2")]
                    $sha2([< Hmac $sha2 Context>]),
                )*
                $(
                    #[cfg(feature = "hmac_sha3")]
                    $sha3([< Hmac $sha3 Context>]),
                )*
                $(
                    #[cfg(feature = "cmac_aes")]
                    $aes([< Cmac $aes Context>]),
                )*
            }

            impl MacContext for crate::mac::RustCryptoContext {
                fn update(&mut self, data: &[u8]) {
                    match self{
                        $(
                            #[cfg(all(feature = "hmac_sha2", not(feature="ring")))]
                            RustCryptoContext::$ring(ctx) => ctx.update(data),
                        )*
                        $(
                            #[cfg(feature = "hmac_sha2")]
                            RustCryptoContext::$sha2(ctx) => ctx.update(data),
                        )*
                        $(
                            #[cfg(feature = "hmac_sha3")]
                            RustCryptoContext::$sha3(ctx) => ctx.update(data),
                        )*
                        $(
                            #[cfg(feature = "cmac_aes")]
                            RustCryptoContext::$aes(ctx) => ctx.update(data),
                        )*
                    }
                }
                fn finalize(self) -> Output {
                    match self{
                        $(
                            #[cfg(all(feature = "hmac_sha2", not(feature="ring")))]
                            RustCryptoContext::$ring(ctx) => ctx.finalize(),
                        )*
                        $(
                            #[cfg(feature = "hmac_sha2")]
                            RustCryptoContext::$sha2(ctx) => ctx.finalize(),
                        )*
                        $(
                            #[cfg(feature = "hmac_sha3")]
                            RustCryptoContext::$sha3(ctx) => ctx.finalize(),
                        )*
                        $(
                            #[cfg(feature = "cmac_aes")]
                            RustCryptoContext::$aes(ctx) => ctx.finalize(),
                        )*
                    }
                }
            }

            impl From<alloc::boxed::Box<crate::mac::RustCryptoKey>> for crate::mac::RustCryptoContext {
                fn from(key: alloc::boxed::Box<crate::mac::RustCryptoKey>) -> Self {
                    let key = *key;
                    match key {
                        $(
                            #[cfg(all(not(feature="ring"), feature = "hmac_sha2"))]
                            RustCryptoKey::$ring(key) => Self::$ring(key.0.into()),
                        )*
                        $(
                            #[cfg(feature = "hmac_sha2")]
                            RustCryptoKey::$sha2(key) => Self::$sha2(key.0.into()),
                        )*
                        $(
                            #[cfg(feature = "hmac_sha3")]
                            RustCryptoKey::$sha3(key) => Self::$sha3(key.0.into()),
                        )*
                        $(
                            #[cfg(feature = "cmac_aes")]
                            RustCryptoKey::$aes(key) => Self::$aes(key.0.into()),
                        )*
                    }
                }
            }
			$( rust_crypto_context_inner!(Hmac, sha2, $ring, feature = "hmac_sha2", not(feature="ring")); )*
            $( rust_crypto_context_inner!(Hmac, sha2, $sha2, feature = "hmac_sha2"); )*
            $( rust_crypto_context_inner!(Hmac, sha3, $sha3, feature = "hmac_sha3"); )*
            $( rust_crypto_context_inner!(Cmac, aes, $aes, feature = "cmac_aes"); )*
        }
	}
}
pub(super) use rust_crypto_context_inner;
pub(super) use rust_crypto_contexts;
