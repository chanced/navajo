

use alloc::{boxed::Box, vec::Vec};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::{error::InvalidKeyLength, Key};

use super::Algorithm;

#[derive(Clone, Zeroize, ZeroizeOnDrop, Debug)]
pub(super) struct Material {
    #[zeroize(skip)]
    pub(super) algorithm: Algorithm,
    #[zeroize(skip)]
    inner: CryptoKey,
    pub(super) bytes: Vec<u8>,
    pub(super) prefix: Option<Vec<u8>>,
}
impl PartialEq for Material {
    fn eq(&self, other: &Self) -> bool {
        self.algorithm == other.algorithm && self.bytes == other.bytes
    }
}
impl Eq for Material {}

impl Material {
    pub(super) fn prefix(&self) -> Option<&[u8]> {
        self.prefix.as_deref()
    }

    pub(super) fn new(
        bytes: &[u8],
        prefix: Option<&[u8]>,
        algorithm: Algorithm,
    ) -> Result<Self, InvalidKeyLength> {
        let key = CryptoKey::new(algorithm, bytes)?;
        Ok(Self {
            algorithm,
            inner: key,
            bytes: bytes.to_vec(),
            prefix: prefix.map(|p| p.to_vec()),
        })
    }
}
impl Key<Material> {
    pub(super) fn crypto_key(&self) -> &CryptoKey {
        &self.material_ref().inner
    }

    pub(super) fn new_context(&self) -> super::Context {
        super::Context::new(self)
    }

    pub(super) fn header(&self) -> Vec<u8> {
        match self.origin() {
            crate::Origin::Generated => self.id().to_be_bytes().to_vec(),
            crate::Origin::External => self.material().prefix.clone().unwrap_or(Vec::new()),
        }
    }
}

impl crate::KeyMaterial for Material {
    type Algorithm = Algorithm;
    fn algorithm(&self) -> Self::Algorithm {
        self.algorithm
    }
}

#[derive(Clone, Debug)]
pub(super) enum CryptoKey {
    Ring(Box<ring::hmac::Key>),
    RustCrypto(Box<crate::mac::RustCryptoKey>),
    #[cfg(feature = "blake3")]
    Blake3(Box<blake3::Hasher>),
}
#[cfg(feature = "blake3")]
impl From<blake3::Hasher> for CryptoKey {
    fn from(key: blake3::Hasher) -> Self {
        Self::Blake3(Box::new(key))
    }
}
impl CryptoKey {
    pub(super) fn new(algorithm: Algorithm, bytes: &[u8]) -> Result<Self, InvalidKeyLength> {
        algorithm.validate_key_len(bytes.len())?;
        match algorithm {
            #[cfg(all(feature = "ring"))]
            Algorithm::Sha256 => Ok(Self::Ring(Box::new(ring::hmac::Key::new(
                ring::hmac::HMAC_SHA256,
                bytes,
            )))),
            #[cfg(all(feature = "ring"))]
            Algorithm::Sha384 => Ok(Self::Ring(Box::new(ring::hmac::Key::new(
                ring::hmac::HMAC_SHA384,
                bytes,
            )))),
            #[cfg(all(feature = "ring"))]
            Algorithm::Sha512 => Ok(Self::Ring(Box::new(ring::hmac::Key::new(
                ring::hmac::HMAC_SHA512,
                bytes,
            )))),
            #[cfg(feature = "blake3")]
            Algorithm::Blake3 => Ok(Self::Blake3(Box::new(blake3::Hasher::new_keyed(
                bytes.try_into().map_err(|_| InvalidKeyLength)?,
            )))),
            _ => Ok(Self::RustCrypto(Box::new(crate::mac::RustCryptoKey::new(
                algorithm, bytes,
            )?))),
        }
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
                    impl TryFrom<&[u8]> for [<$typ $alg Key>] {
                        type Error = crate::error::InvalidKeyLength;
                        fn try_from(key: &[u8]) -> Result<Self, Self::Error> {
                            use [< $typ:lower >]::Mac;
                            Ok(Self([< $typ:lower >]::$typ::new_from_slice(key)?))
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
            impl core::fmt::Debug for RustCryptoKey {
                fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> std::fmt::Result {
                    f.debug_struct("RustCryptoKey").finish()
                }
            }
            impl From<RustCryptoKey> for CryptoKey {
                fn from(key: RustCryptoKey) -> Self {
                    Self::RustCrypto(alloc::boxed::Box::new(key))
                }
            }
            impl RustCryptoKey {
                pub(super) fn new(algorithm: Algorithm, bytes: &[u8]) -> Result<Self, crate::error::InvalidKeyLength> {
                    use crate::mac::Algorithm::*;
                    Ok(match algorithm {
                        $(
                            #[cfg(all(feature = "hmac_sha2", not(feature="ring")))]
                            $ring => Self::$ring(bytes.try_into()?),
                        )*
                        $(
                            #[cfg(feature = "hmac_sha2")]
                            $sha2 => Self::$sha2(bytes.try_into()?),
                        )*
                        $(
                            #[cfg(feature = "hmac_sha3")]
                            $sha3 => Self::$sha3(bytes.try_into()?),
                        )*
                        $(
                            #[cfg(feature = "cmac_aes")]
                            $aes => Self::$aes(bytes.try_into()?),
                        )*
                        _ => unreachable!(),
                    })
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
