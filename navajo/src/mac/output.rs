use crate::mac::RustCryptoOutput;

pub(super) trait DigestOutput: AsRef<[u8]> + Clone {
    fn into_bytes(self) -> Vec<u8> {
        self.as_ref().to_vec()
    }
    fn truncatable(&self) -> bool;
}

#[derive(Clone, Debug)]
pub(super) enum Output {
    #[cfg(all(feature = "ring", feature = "hmac_sha2"))]
    Ring(RingOutput),
    RustCrypto(RustCryptoOutput),
    #[cfg(feature = "blake3")]
    Blake3(Blake3Output),
}
impl Output {
    pub(super) fn as_bytes(&self) -> &[u8] {
        match self {
            #[cfg(all(feature = "ring", feature = "hmac_sha2"))]
            Self::Ring(output) => output.as_ref(),
            Self::RustCrypto(output) => output.as_ref(),
            Self::Blake3(output) => output.as_ref(),
        }
    }
}

impl DigestOutput for Output {
    fn truncatable(&self) -> bool {
        match self {
            #[cfg(all(feature = "ring", feature = "hmac_sha2"))]
            Self::Ring(output) => output.truncatable(),
            Self::RustCrypto(output) => output.truncatable(),
            Self::Blake3(output) => output.truncatable(),
        }
    }
}

impl AsRef<[u8]> for Output {
    fn as_ref(&self) -> &[u8] {
        self.as_bytes()
    }
}

cfg_if::cfg_if! {
    if #[cfg(all(feature = "ring", feature="hmac_sha2"))] {
        #[derive(Clone, Debug)]
        pub(super) struct RingOutput(ring::hmac::Tag);
        impl AsRef<[u8]> for RingOutput {
            fn as_ref(&self) -> &[u8] {
                self.0.as_ref()
            }
        }
        impl DigestOutput for RingOutput {
            fn truncatable(&self) -> bool { true }
        }
        impl From<ring::hmac::Tag> for Output {
            fn from(output: ring::hmac::Tag) -> Self {
                Self::Ring(RingOutput(output))
            }
        }
    }

}

cfg_if::cfg_if! {
    if #[cfg(feature = "blake3")] {
        #[derive(Clone, Debug)]
        pub(super) struct Blake3Output (blake3::Hash);
        impl DigestOutput for Blake3Output {
            fn truncatable(&self) -> bool { true } //github.com/BLAKE3-team/BLAKE3/issues/123
        }
        impl From<blake3::Hash> for Blake3Output {
            fn from(hash: blake3::Hash) -> Self {
                Self(hash)
            }
        }
        impl AsRef<[u8]> for Blake3Output {
            fn as_ref(&self) -> &[u8] {
                self.0.as_bytes()
            }
        }
        impl From<Blake3Output> for Output {
            fn from(output: Blake3Output) -> Self {
                Self::Blake3(output)
            }
        }
    }
}

macro_rules! rust_crypto_internal_tag {
    ($typ:ident, $crt:ident, $alg:ident, $feat:meta$(, not($cfg:meta))?) => {
        paste::paste! {
            cfg_if::cfg_if! {
                if #[cfg(all($feat, $(not($cfg))?))] {
                    #[derive(Clone, Debug)]
                    pub(super) struct [< $typ $alg InternalTag >] (digest::Output<[< $typ:lower >]::$typ<$crt::$alg>>);
                    impl AsRef<[u8]> for [< $typ $alg InternalTag >] {
                        fn as_ref(&self) -> &[u8] {
                            self.0.as_ref()
                        }
                    }
                    impl From<digest::CtOutput<[< $typ:lower >]::$typ<$crt::$alg>>> for [< $typ $alg InternalTag >] {
                        fn from(output: digest::CtOutput<[< $typ:lower >]::$typ<$crt::$alg>>) -> Self {
                            Self(output.into_bytes())
                        }
                    }
                    impl crate::mac::output::DigestOutput for [< $typ $alg InternalTag >] {
                        fn truncatable(&self) -> bool { true }
                    }
                    impl From<[< $typ $alg InternalTag >]> for  crate::mac::output::Output {
                        fn from(output: [< $typ $alg InternalTag >]) -> Self {
                            RustCryptoOutput::$alg(output).into()
                        }
                    }
                    impl From<digest::CtOutput<[< $typ:lower >]::$typ<$crt::$alg>>> for crate::mac::output::Output {
                        fn from(output: digest::CtOutput<[< $typ:lower >]::$typ<$crt::$alg>>) -> Self {
                            [< $typ $alg InternalTag >]::from(output).into()
                        }
                    }
                }
            }
        }
    }
}

macro_rules! rust_crypto_internal_tags {
    ({
        hmac: { ring: [$($ring:ident),*], sha2: [$($sha2:ident),*], sha3: [$($sha3:ident),*]$(,)? },
        cmac: { aes: [$($aes:ident),*]$(,)? }
	}) => {
        paste::paste! {
            #[derive(Clone, Debug)]
            pub(super) enum RustCryptoOutput {
                $(
                    #[cfg(all(feature="hmac_sha2", not(feature = "ring")))]
                    $ring(crate::mac::[< Hmac $ring InternalTag >]),
                )*
                $(
                    #[cfg(feature="hmac_sha2")]
                    $sha2(crate::mac::[< Hmac $sha2 InternalTag >]),
                )*

                $(
                    #[cfg(feature="hmac_sha3")]
                    $sha3(crate::mac::[< Hmac $sha3 InternalTag >]),
                )*
                $(
                    #[cfg(feature="cmac_aes")]
                    $aes(crate::mac::[< Cmac $aes InternalTag >]),
                )*
            }
            impl From<RustCryptoOutput> for crate::mac::output::Output {
                fn from(output: RustCryptoOutput) -> Self {
                    Self::RustCrypto(output)
                }
            }
			$( rust_crypto_internal_tag!(Hmac, sha2, $ring, feature = "hmac_sha2", not(feature="ring")); )*
            $( rust_crypto_internal_tag!(Hmac, sha2, $sha2, feature = "hmac_sha2"); )*
            $( rust_crypto_internal_tag!(Hmac, sha3, $sha3, feature = "hmac_sha3"); )*
            $( rust_crypto_internal_tag!(Cmac, aes, $aes, feature = "cmac_aes"); )*

            impl AsRef<[u8]> for RustCryptoOutput {
                fn as_ref(&self) -> &[u8] {
                    match self {
                        $(
                            #[cfg(not(feature = "ring"))]
                            Self::$ring(tag) => tag.as_ref(),
                        )*
                        $(
                            #[cfg(feature="hmac_sha2")]
                            Self::$sha2(tag) => tag.as_ref(),

                        )*
                        $(
                            #[cfg(feature="hmac_sha3")]
                            Self::$sha3(tag) => tag.as_ref(),
                        )*
                        $(
                            #[cfg(feature="cmac_aes")]
                            Self::$aes(tag) => tag.as_ref(),

                        )*
                    }
                }
            }
            impl crate::mac::output::DigestOutput for RustCryptoOutput {
                fn truncatable(&self) -> bool { true }
            }
        }
    }
}

use alloc::vec::Vec;
pub(super) use rust_crypto_internal_tag;
pub(super) use rust_crypto_internal_tags;
