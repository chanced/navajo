use super::{tag::Blake3Output, Output};

pub(super) struct Context(ContextInner);

#[allow(clippy::large_enum_variant)]
pub(super) enum ContextInner {
    #[cfg(feature = "blake3")]
    Blake3(Blake3Output),
    #[cfg(all(feature = "ring", feature = "hmac_sha2"))]
    Ring(crate::mac::RingContext),
    RustCrypto(Box<crate::mac::RustCryptoContext>),
}

pub(super) trait MacContext {
    fn update(&mut self, data: &[u8]);
    fn finalize(self) -> Output;
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

            impl From<crate::mac::RustCryptoContext> for ContextInner {
                fn from(ctx: crate::mac::RustCryptoContext) -> Self {
                    ContextInner::RustCrypto(Box::new(ctx))
                }
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

			$( rust_crypto_context_inner!(Hmac, sha2, $ring, feature = "hmac_sha2", not(feature="ring")); )*
            $( rust_crypto_context_inner!(Hmac, sha2, $sha2, feature = "hmac_sha2"); )*
            $( rust_crypto_context_inner!(Hmac, sha3, $sha3, feature = "hmac_sha3"); )*
            $( rust_crypto_context_inner!(Cmac, aes, $aes, feature = "cmac_aes"); )*
        }
	}
}
pub(super) use rust_crypto_context_inner;
pub(super) use rust_crypto_contexts;
