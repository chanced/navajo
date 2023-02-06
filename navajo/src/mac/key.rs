use crate::KeyStatus;

use super::Algorithm;

#[derive(Clone)]
pub(super) struct Key {
    id: u64,
    algorithm: Algorithm,
    inner: MacKey,
    prefix: Option<Vec<u8>>,
    status: KeyStatus,
}

impl Key {
    pub(super) fn new(
        id: u64,
        algorithm: Algorithm,
        inner: MacKey,
        prefix: Option<Vec<u8>>,
        status: KeyStatus,
    ) -> Self {
        Self {
            id,
            algorithm,
            inner,
            prefix,
            status,
        }
    }
    pub(super) fn prefix(&self) -> Option<&[u8]> {
        self.prefix.as_deref()
    }
}

#[derive(Clone)]
pub(super) enum MacKey {
    #[cfg(all(feature = "ring"))]
    Ring(ring_compat::ring::hmac::Key),
    RustCrypto(Box<crate::mac::RustCryptoKey>),
    #[cfg(feature = "blake3")]
    Blake3(blake3::Hash),
}

impl From<blake3::Hash> for MacKey {
    fn from(key: blake3::Hash) -> Self {
        Self::Blake3(key)
    }
}

macro_rules! rust_crypto_key {
    ($typ:ident, $crt:ident, $alg:ident, $feat:meta$(, not($cfg:meta))?) => {
        paste::paste! {
            cfg_if::cfg_if! {
                if #[cfg(all($feat, $(not($cfg))?))] {
                    #[derive(Clone)]
                    pub(super) struct [<$typ $alg Key>] ([< $typ:lower >]::$typ<$crt::$alg>);
                    impl From<[< $typ:lower >]::$typ<$crt::$alg>> for [<$typ $alg Key>] {
                        fn from(key: [< $typ:lower >]::$typ<$crt::$alg>) -> Self {
                            Self(key)
                        }
                    }
                    impl From<[<$typ $alg Key>]> for RustCryptoKey {
                        fn from(key: [<$typ $alg Key>]) -> Self {
                            Self::$alg(key)
                        }
                    }
                }
            }
        }
    }
}
macro_rules! rust_crypto_keys {
    ({
        hmac: { ring: [$($ring:ident),*], sha2: [$($sha2:ident),*], sha3: [$($sha3:ident),*]$(,)? },
        cmac: { aes: [$($aes:ident),*]$(,)? }
	}) => {
        paste::paste! {
            #[derive(Clone)]
            pub(crate) enum RustCryptoKey {
                $(
                    #[cfg(all(feature = "hmac_sha2", not(feature="ring")))]
                    $ring([< Hmac $ring Key>]),
                )*
                $(
                    #[cfg(feature = "hmac_sha2")]
                    $sha2([< Hmac $sha2 Key >]),
                )*
                $(
                    #[cfg(feature = "hmac_sha3")]
                    $sha3([< Hmac $sha3 Key >]),
                )*
                $(
                    #[cfg(feature = "cmac_aes")]
                    $aes([< Cmac $aes Key >]),
                )*
            }
            impl From<RustCryptoKey> for MacKey {
                fn from(key: RustCryptoKey) -> Self {
                    Self::RustCrypto(Box::new(key))
                }
            }
        }
        $( rust_crypto_key!(Hmac, sha2, $ring, feature = "hmac_sha2", not(feature="ring")); )*
        $( rust_crypto_key!(Hmac, sha2, $sha2, feature = "hmac_sha2"); )*
        $( rust_crypto_key!(Hmac, sha3, $sha3, feature = "hmac_sha3"); )*
        $( rust_crypto_key!(Cmac, aes, $aes, feature = "cmac_aes"); )*

    };
}
pub(super) use rust_crypto_key;
pub(super) use rust_crypto_keys;
