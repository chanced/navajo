use crate::NEW_ISSUE_URL;
use alloc::{boxed::Box, vec::Vec};
use serde::{Deserialize, Serialize};
use zeroize::ZeroizeOnDrop;

use crate::{error::KeyError, primitive::Kind, sensitive::Bytes, Key};

use super::Algorithm;

#[derive(Clone, ZeroizeOnDrop, Debug, Deserialize, Serialize)]
pub(crate) struct Material {
    #[zeroize(skip)]
    algorithm: Algorithm,
    value: Bytes,
    #[serde(skip_serializing_if = "Option::is_none")]
    prefix: Option<Bytes>,
}

impl PartialEq for Material {
    fn eq(&self, other: &Self) -> bool {
        self.algorithm == other.algorithm && self.value == other.value
    }
}
impl Eq for Material {}

impl Material {
    pub(super) fn prefix(&self) -> Option<&[u8]> {
        self.prefix.as_deref()
    }

    pub(super) fn new(
        value: &[u8],
        prefix: Option<&[u8]>,
        algorithm: Algorithm,
    ) -> Result<Self, KeyError> {
        algorithm.validate_key_len(value.len())?;
        let bytes = Bytes::from(value);
        Ok(Self {
            algorithm,
            value: bytes,
            prefix: prefix.map(Into::into),
        })
    }
}
impl Key<Material> {
    pub(super) fn new_backend_key(&self) -> BackendKey {
        // safety: key length is validated on Material creation
        BackendKey::new(self.algorithm(), self.material().value.as_ref()).unwrap()
    }

    pub(super) fn new_context(&self) -> super::Context {
        super::Context::new(self)
    }

    pub(super) fn header(&self) -> Vec<u8> {
        match self.origin() {
            crate::Origin::Navajo => self.id().to_be_bytes().to_vec(),
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
    fn kind() -> Kind {
        Kind::Mac
    }
}

#[derive(Clone, Debug)]
pub(super) enum BackendKey {
    #[cfg(feature = "ring")]
    Ring(ring::hmac::Key),
    RustCrypto(RustCryptoKey),
    #[cfg(feature = "blake3")]
    Blake3(blake3::Hasher),
}

#[cfg(feature = "ring")]
impl From<ring::hmac::Key> for BackendKey {
    fn from(key: ring::hmac::Key) -> Self {
        Self::Ring(key)
    }
}

impl BackendKey {
    pub(super) fn new(algorithm: Algorithm, bytes: &[u8]) -> Result<Self, KeyError> {
        algorithm.validate_key_len(bytes.len())?;
        #[cfg(feature = "blake3")]
        use blake3::Hasher as Blake3;
        #[cfg(feature = "ring")]
        use ring::hmac::{Key as Ring, HMAC_SHA256, HMAC_SHA384, HMAC_SHA512};
        let key = match algorithm {
            #[cfg(feature = "ring")]
            Algorithm::Sha256 => Self::Ring(Ring::new(HMAC_SHA256, bytes)),
            #[cfg(feature = "ring")]
            Algorithm::Sha384 => Self::Ring(Ring::new(HMAC_SHA384, bytes)),
            #[cfg(feature = "ring")]
            Algorithm::Sha512 => Self::Ring(Ring::new(HMAC_SHA512, bytes)),
            #[cfg(feature = "blake3")]
            Algorithm::Blake3 => Self::Blake3(Blake3::new_keyed(bytes.try_into()?)),
            _ => Self::RustCrypto(RustCryptoKey::new(algorithm, bytes)?),
        };
        Ok(key)
    }
}
#[derive(Clone, Debug)]
pub(super) enum RustCryptoKey {
    #[cfg(all(not(feature = "ring"), feature = "sha2", feature = "hmac"))]
    Sha256(hmac::Hmac<sha2::Sha256>),

    #[cfg(all(not(feature = "ring"), feature = "sha2", feature = "hmac"))]
    Sha384(hmac::Hmac<sha2::Sha384>),

    #[cfg(all(not(feature = "ring"), feature = "sha2", feature = "hmac"))]
    Sha512(hmac::Hmac<sha2::Sha512>),

    #[cfg(all(feature = "sha2", feature = "hmac"))]
    Sha224(hmac::Hmac<sha2::Sha224>),

    #[cfg(all(feature = "sha3", feature = "hmac"))]
    Sha3_256(hmac::Hmac<sha3::Sha3_256>),

    #[cfg(all(feature = "sha3", feature = "hmac"))]
    Sha3_224(hmac::Hmac<sha3::Sha3_224>),

    #[cfg(all(feature = "sha3", feature = "hmac"))]
    Sha3_384(hmac::Hmac<sha3::Sha3_384>),

    #[cfg(all(feature = "sha3", feature = "hmac"))]
    Sha3_512(hmac::Hmac<sha3::Sha3_512>),

    #[cfg(all(feature = "aes", feature = "cmac"))]
    Aes128(cmac::Cmac<aes::Aes128>),

    #[cfg(all(feature = "aes", feature = "cmac"))]
    Aes192(cmac::Cmac<aes::Aes192>),

    #[cfg(all(feature = "aes", feature = "cmac"))]
    Aes256(cmac::Cmac<aes::Aes256>),
}

impl RustCryptoKey {
    fn new(algorithm: Algorithm, bytes: &[u8]) -> Result<Self, KeyError> {
        let result = match algorithm {
            #[cfg(all(not(feature = "ring"), feature = "sha2", feature = "hmac"))]
            Algorithm::Sha256 => {
                use hmac::Mac;
                Self::Sha256(hmac::Hmac::<sha2::Sha256>::new_from_slice(bytes).unwrap())
            },
            #[cfg(all(not(feature = "ring"), feature = "sha2", feature = "hmac"))]
            Algorithm::Sha384 => todo!(),
            #[cfg(all(not(feature = "ring"), feature = "sha2", feature = "hmac"))]
            Algorithm::Sha512 => todo!(),
            #[cfg(all(feature = "sha2", feature = "hmac"))]
            Algorithm::Sha224 => todo!(),
            #[cfg(all(feature = "sha3", feature = "hmac"))]
            Algorithm::Sha3_256 => todo!(),
            #[cfg(all(feature = "sha3", feature = "hmac"))]
            Algorithm::Sha3_224 => todo!(),
            #[cfg(all(feature = "sha3", feature = "hmac"))]
            Algorithm::Sha3_384 => todo!(),
            #[cfg(all(feature = "sha3", feature = "hmac"))]
            Algorithm::Sha3_512 => todo!(),
            #[cfg(all(feature = "aes", feature = "cmac"))]
            Algorithm::Aes128 => todo!(),
            #[cfg(all(feature = "aes", feature = "cmac"))]
            Algorithm::Aes128 => todo!(),
            #[cfg(all(feature = "aes", feature = "cmac"))]
            Algorithm::Aes128 => todo!(),
            _ => unreachable!(
                "{algorithm} is either not supported by rust crypto, disabled, or should be handled by ring\nthis is a bug\nplease report it to {NEW_ISSUE_URL}",
            ),
        };
        Ok(result)
    }
}
