use super::{key::MacKey, Output};

#[allow(clippy::large_enum_variant)]
pub(super) enum Context {
    #[cfg(feature = "blake3")]
    Blake3(crate::mac::Blake3Context),
    #[cfg(all(feature = "ring", feature = "hmac_sha2"))]
    Ring(crate::mac::RingContext),
    RustCrypto(Box<crate::mac::RustCryptoContext>),
}
impl Context {
    pub(super) fn new(key: &MacKey) -> Context {
        match &key {
            MacKey::Ring(key) => key.as_ref().into(),
            MacKey::RustCrypto(key) => Context::RustCrypto(Box::new(key.as_ref().into())),
            MacKey::Blake3(key) => key.as_ref().into(),
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
    pub(super) fn finalize(self) -> Output {
        match self {
            #[cfg(feature = "blake3")]
            Self::Blake3(ctx) => ctx.finalize(),
            #[cfg(all(feature = "ring", feature = "hmac_sha2"))]
            Self::Ring(ctx) => ctx.finalize(),
            Self::RustCrypto(ctx) => ctx.finalize(),
        }
    }
}

#[cfg(all(feature = "ring", feature = "hmac_sha2"))]
impl From<&ring_compat::ring::hmac::Key> for Context {
    fn from(key: &ring_compat::ring::hmac::Key) -> Self {
        Self::Ring(key.into())
    }
}

impl From<&blake3::Hasher> for Context {
    fn from(key: &blake3::Hasher) -> Self {
        Self::Blake3(key.into())
    }
}

pub(super) trait MacContext {
    fn update(&mut self, data: &[u8]);
    fn finalize(self) -> Output;
}
#[cfg(feature = "blake3")]
#[derive(Clone)]
pub(crate) struct Blake3Context(blake3::Hasher);

impl From<&blake3::Hasher> for Blake3Context {
    fn from(hasher: &blake3::Hasher) -> Self {
        Self(hasher.clone())
    }
}
impl MacContext for Blake3Context {
    fn update(&mut self, data: &[u8]) {
        self.0.update(data);
    }
    fn finalize(self) -> Output {
        Output::Blake3(self.0.finalize().into())
    }
}
cfg_if::cfg_if! {
    if #[cfg(all(feature = "ring", feature="hmac_sha2"))]{
        pub(super) struct RingContext(ring_compat::ring::hmac::Context);

        impl MacContext for RingContext {
            fn update(&mut self, data: &[u8]) {
                self.0.update(data);
            }
            fn finalize(self) -> Output {
                self.0.sign().into()
            }
        }
        impl From<&ring_compat::ring::hmac::Key> for RingContext {
            fn from(key: &ring_compat::ring::hmac::Key) -> Self {
                Self(ring_compat::ring::hmac::Context::with_key(key))
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
                    pub(super) struct [<$typ $alg Context>] ([< $typ:lower >]::$typ<$crt::$alg>);
                    impl MacContext for [<$typ $alg Context>] {
                        fn update(&mut self, data: &[u8]) {
                            use [< $typ:lower >]::Mac;
                            self.0.update(data);
                        }
                        fn finalize(self) -> crate::mac::Output {
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
                            Self(ctx)
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

            impl From<&crate::mac::RustCryptoKey> for crate::mac::RustCryptoContext {
                fn from(key: &crate::mac::RustCryptoKey) -> Self {
                    match key {
                        $(
                            #[cfg(all(feature = "hmac_sha2", not(feature="ring")))]
                            RustCryptoKey::$ring(key) => key.0.clone().into(),
                        )*
                        $(
                            #[cfg(feature = "hmac_sha2")]
                            RustCryptoKey::$sha2(key) => Self::$sha2(key.0.clone().into()),
                        )*
                        $(
                            #[cfg(feature = "hmac_sha3")]
                            RustCryptoKey::$sha3(key) => Self::$sha3(key.0.clone().into()),
                        )*
                        $(
                            #[cfg(feature = "cmac_aes")]
                            RustCryptoKey::$aes(key) => Self::$aes(key.0.clone().into()),
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
use alloc::boxed::Box;
pub(super) use rust_crypto_context_inner;
pub(super) use rust_crypto_contexts;
