use alloc::{boxed::Box, sync::Arc, vec::Vec};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use zeroize::ZeroizeOnDrop;

use crate::{error::InvalidKeyLength, sensitive::Bytes, Key};

use super::Algorithm;

#[derive(Clone, ZeroizeOnDrop, Debug, Deserialize, Serialize)]
pub(crate) struct Material {
    #[zeroize(skip)]
    pub(super) algorithm: Algorithm,
    pub(super) bytes: Bytes,
    pub(super) prefix: Option<Bytes>,
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
        algorithm.validate_key_len(bytes.len())?;
        let bytes = Bytes(Arc::from(bytes));
        Ok(Self {
            algorithm,
            bytes,
            prefix: prefix.map(Into::into),
        })
    }
}
impl Key<Material> {
    pub(super) fn crypto_key(&self) -> CryptoKey {
        // safety: key length is validated on Material creation
        CryptoKey::new(self.algorithm(), self.material().bytes.as_ref()).unwrap()
    }

    pub(super) fn new_context(&self) -> super::Context {
        super::Context::new(self)
    }

    pub(super) fn header(&self) -> Vec<u8> {
        match self.origin() {
            crate::Origin::Generated => self.id().to_be_bytes().to_vec(),
            crate::Origin::External => self
                .material()
                .prefix
                .clone()
                .map(|b| b.to_vec())
                .unwrap_or(Vec::default()),
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
    #[cfg(all(feature = "ring", feature = "sha2"))]
    Ring(Box<ring::hmac::Key>),
    RustCrypto(Box<crate::mac::RustCryptoKey>),
    #[cfg(feature = "blake3")]
    Blake3(Box<blake3::Hasher>),
}
#[cfg(feature = "blake3")]
impl From<Box<blake3::Hasher>> for CryptoKey {
    fn from(key: Box<blake3::Hasher>) -> Self {
        Self::Blake3(key)
    }
}
#[cfg(all(feature = "ring", feature = "sha2"))]
impl From<Box<ring::hmac::Key>> for CryptoKey {
    fn from(key: Box<ring::hmac::Key>) -> Self {
        Self::Ring(key)
    }
}
impl From<Box<crate::mac::RustCryptoKey>> for CryptoKey {
    fn from(key: Box<crate::mac::RustCryptoKey>) -> Self {
        Self::RustCrypto(key)
    }
}

impl CryptoKey {
    pub(super) fn new(algorithm: Algorithm, bytes: &[u8]) -> Result<Self, InvalidKeyLength> {
        algorithm.validate_key_len(bytes.len())?;
        match algorithm {
            #[cfg(all(feature = "ring", feature = "sha2"))]
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
                    #[cfg(all(feature = "sha2", not(feature="ring")))]
                    $ring([< Hmac $ring Key>]),
                )*
                $(
                    #[cfg(feature = "sha2")]
                    $sha2([< Hmac $sha2 Key >]),
                )*
                $(
                    #[cfg(feature = "sha3")]
                    $sha3([< Hmac $sha3 Key >]),
                )*
                $(
                    #[cfg(feature = "aes")]
                    $aes([< Cmac $aes Key >]),
                )*
            }
            impl core::fmt::Debug for RustCryptoKey {
                fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
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
                            #[cfg(all(feature = "sha2", not(feature="ring")))]
                            $ring => Self::$ring(bytes.try_into()?),
                        )*
                        $(
                            #[cfg(feature = "sha2")]
                            $sha2 => Self::$sha2(bytes.try_into()?),
                        )*
                        $(
                            #[cfg(feature = "sha3")]
                            $sha3 => Self::$sha3(bytes.try_into()?),
                        )*
                        $(
                            #[cfg(feature = "aes")]
                            $aes => Self::$aes(bytes.try_into()?),
                        )*
                        _ => unreachable!(),
                    })
                }
            }
        }
        $( rust_crypto_key!(Hmac, sha2, $ring, feature = "sha2", not(feature="ring")); )*
        $( rust_crypto_key!(Hmac, sha2, $sha2, feature = "sha2"); )*
        $( rust_crypto_key!(Hmac, sha3, $sha3, feature = "sha3"); )*
        $( rust_crypto_key!(Cmac, aes, $aes, feature = "aes"); )*

    };
}
pub(super) use rust_crypto_key;
pub(super) use rust_crypto_keys;
