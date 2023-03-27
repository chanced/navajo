use core::{fmt::Display, ops::Deref};

use super::Algorithm;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};

#[cfg(not(feature = "ring"))]
#[derive(Clone, Copy, Debug)]
pub enum Signature {
    Ed25519([u8; 64]),
    P256([u8; 64]),
    P384([u8; 96]),
}

impl Signature {
    pub fn algorithm(&self) -> Algorithm {
        match self {
            Signature::Ed25519(_) => Algorithm::Ed25519,
            Signature::P256(_) => Algorithm::Es256,
            Signature::P384(_) => Algorithm::Es384,
        }
    }
}
impl Display for Signature {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Signature::Ed25519(sig) => write!(f, "{}", URL_SAFE_NO_PAD.encode(sig)),
            Signature::P256(sig) => write!(f, "{}", URL_SAFE_NO_PAD.encode(sig)),
            Signature::P384(sig) => write!(f, "{}", URL_SAFE_NO_PAD.encode(sig)),
        }
    }
}
#[cfg(not(feature = "ring"))]
impl From<ed25519_dalek::Signature> for Signature {
    fn from(sig: ed25519_dalek::Signature) -> Self {
        let mut bytes = [0u8; 64];
        bytes.copy_from_slice(&sig.to_bytes());
        Self::Ed25519(bytes)
    }
}
#[cfg(not(feature = "ring"))]
impl From<p256::ecdsa::Signature> for Signature {
    fn from(sig: p256::ecdsa::Signature) -> Self {
        let mut bytes = [0u8; 64];
        bytes.copy_from_slice(&sig.to_bytes());
        Self::P256(bytes)
    }
}

#[cfg(not(feature = "ring"))]
impl From<p384::ecdsa::Signature> for Signature {
    fn from(sig: p384::ecdsa::Signature) -> Self {
        let mut bytes = [0u8; 96];
        bytes.copy_from_slice(&sig.to_bytes());
        Self::P384(bytes)
    }
}

impl Deref for Signature {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        self.as_ref()
    }
}
impl AsRef<[u8]> for Signature {
    fn as_ref(&self) -> &[u8] {
        match self {
            Signature::Ed25519(bytes) => bytes,
            Signature::P256(bytes) => bytes,
            Signature::P384(bytes) => bytes,
        }
    }
}
