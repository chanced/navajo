use core::ops::Deref;

use super::Algorithm;
use base64::{engine::general_purpose as b64, Engine as _};

#[cfg(feature = "ring")]
#[derive(Clone, Copy)]
pub enum Signature {
    Ed25519(ring::signature::Signature),
    P256(ring::signature::Signature),
    P384(ring::signature::Signature),
}

#[cfg(feature = "ring")]
impl core::fmt::Debug for Signature {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Ed25519(s) => f.debug_tuple("Ed25519").field(&s.as_ref()).finish(),
            Self::P256(s) => f.debug_tuple("P256").field(&s.as_ref()).finish(),
            Self::P384(s) => f.debug_tuple("P384").field(&s.as_ref()).finish(),
        }
    }
}

#[cfg(not(feature = "ring"))]
#[derive(Clone, Copy, Debug)]
pub enum Signature {
    Ed25519(ed25519_dalek::Signature, [u8; 64]),
    P256(p256::ecdsa::Signature, [u8; 64]),
    P384(p384::ecdsa::Signature, [u8; 96]),
}

impl Signature {
    pub fn to_vec(&self) -> Vec<u8> {
        #[cfg(feature = "ring")]
        {
            match self {
                Signature::Ed25519(sig) => sig.as_ref().to_vec(),
                Signature::P256(sig) => sig.as_ref().to_vec(),
                Signature::P384(sig) => sig.as_ref().to_vec(),
            }
        }
        #[cfg(not(feature = "ring"))]
        {
            match self {
                Signature::Ed25519(sig) => sig.to_bytes().to_vec(),
                Signature::P256(sig) => sig.to_bytes().to_vec(),
                Signature::P384(sig) => sig.to_bytes().to_vec(),
            }
        }
    }
    pub fn algorithm(&self) -> Algorithm {
        #[cfg(feature = "ring")]
        {
            match self {
                Signature::Ed25519(_) => Algorithm::Ed25519,
                Signature::P256(_) => Algorithm::Es256,
                Signature::P384(_) => Algorithm::Es384,
            }
        }
        #[cfg(not(feature = "ring"))]
        {
            match self {
                Signature::Ed25519(_) => Algorithm::Ed25519,
                Signature::P256(_) => Algorithm::Es256,
                Signature::P384(_) => Algorithm::Es384,
            }
        }
    }
}
#[cfg(not(feature = "ring"))]
impl From<ed25519_dalek::Signature> for Signature {
    fn from(sig: ed25519_dalek::Signature) -> Self {
        let mut bytes = [0u8; 64];
        bytes.copy_from_slice(&sig.to_bytes());
        Self::Ed25519(sig, bytes)
    }
}
#[cfg(not(feature = "ring"))]
impl From<p256::ecdsa::Signature> for Signature {
    fn from(sig: p256::ecdsa::Signature) -> Self {
        let mut bytes = [0u8; 64];
        bytes.copy_from_slice(&sig.to_bytes());
        Self::P256(sig, bytes)
    }
}

#[cfg(not(feature = "ring"))]
impl From<p384::ecdsa::Signature> for Signature {
    fn from(sig: p384::ecdsa::Signature) -> Self {
        let mut bytes = [0u8; 96];
        bytes.copy_from_slice(&sig.to_bytes());
        Self::P384(sig, bytes)
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
        #[cfg(feature = "ring")]
        {
            match self {
                Signature::Ed25519(sig) => sig.as_ref(),
                Signature::P256(sig) => sig.as_ref(),
                Signature::P384(sig) => sig.as_ref(),
            }
        }
        #[cfg(not(feature = "ring"))]
        {
            match self {
                Signature::Ed25519(sig) => &sig.to_bytes(),
                Signature::P256(sig) => &sig.to_bytes(),
                Signature::P384(sig) => &sig.to_bytes(),
            }
        }
    }
}
