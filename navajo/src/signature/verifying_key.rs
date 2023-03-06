use alloc::sync::Arc;
use rand_core::CryptoRng;

use crate::{
    error::{KeyError, VerificationError},
    rand::is_zero,
    sensitive, Rng, SystemRng,
};

use super::{material::KeyPair, Algorithm};

#[derive(Clone)]
pub(crate) struct VerifyingKey {
    inner: Inner,
    key: sensitive::Bytes,
}

impl VerifyingKey {
    pub fn verify(&self, sig: &[u8]) -> Result<(), VerificationError> {
        self.inner.verify(sig)
    }
}

#[derive(Clone)]
enum Inner {
    Ed25519(Ed25519),
    Ecdsa(Ecdsa),
    Rsa(Rsa),
}

impl Inner {
    fn from_key_pair(algorithm: Algorithm, keys: &KeyPair) -> Result<Self, KeyError> {
        let key = match algorithm {
            Algorithm::Ed25519 => Self::Ed25519(Ed25519::from_key_pair(algorithm, keys)?),
            Algorithm::Es256 | Algorithm::Es384 => {
                Self::Ecdsa(Ecdsa::from_key_pair(algorithm, keys)?)
            }
            Algorithm::Rs256
            | Algorithm::Rs384
            | Algorithm::Rs512
            | Algorithm::Ps256
            | Algorithm::Ps384
            | Algorithm::Ps512 => Self::Rsa(Rsa::from_key_pair(algorithm, keys)?),
        };
        Ok(key)
    }

    fn verify(&self, data: &[u8]) -> Result<(), VerificationError> {
        match self {
            Self::Ed25519(inner) => inner.verify(data),
            Self::Ecdsa(inner) => inner.verify(data),
            Self::Rsa(inner) => inner.verify(data),
        }
    }
}

#[cfg(feature = "ring")]
#[derive(Clone)]
struct Ecdsa {
    key: Arc<ring::signature::UnparsedPublicKey<sensitive::Bytes>>,
}

#[cfg(not(feature = "ring"))]
#[derive(Clone)]
enum Ecdsa {
    P256 {
        signing_key: p256::ecdsa::SigningKey,
        verifying_key: Arc<p256::ecdsa::VerifyingKey>,
    },
    P384 {
        signing_key: p384::ecdsa::SigningKey,
        verifying_key: Arc<p384::ecdsa::VerifyingKey>,
    },
}
impl Ecdsa {
    fn from_key_pair(alg: Algorithm, keys: &KeyPair) -> Result<Self, KeyError> {
        #[cfg(feature = "ring")]
        {
            // let signing_key = ring::signature::EcdsaKeyPair::from_private_key_and_public_key(
            //     alg.ring_ecdsa_signing_algorithm(),
            //     &keys.private,
            //     &keys.public,
            // )?;
            // let verifying_key = ring::signature::UnparsedPublicKey::new(
            //     alg.ring_ecdsa_verifying_algorithm(),
            //     keys.public.clone(),
            // );
            // let signing_key = Arc::new(signing_key);
            // let verifying_key = Arc::new(verifying_key);
            todo!()
        }
        #[cfg(not(feature = "ring"))]
        {
            match alg {
                Algorithm::Es256 => {
                    todo!()
                }
                Algorithm::Es384 => {
                    todo!()
                }
                _ => unreachable!(),
            }
        }
    }

    fn sign(&self, data: &[u8]) -> Result<Vec<u8>, KeyError> {
        todo!()
    }

    fn verify(&self, data: &[u8]) -> Result<(), VerificationError> {
        todo!()
    }
}

#[derive(Clone)]
struct Ed25519 {
    #[cfg(feature = "ring")]
    key: Arc<ring::signature::UnparsedPublicKey<sensitive::Bytes>>,

    #[cfg(not(feature = "ring"))]
    key: Arc<ed25519_dalek::VerifyingKey>,
}

impl Ed25519 {
    fn from_key_pair(_: Algorithm, key_pair: &KeyPair) -> Result<Self, KeyError> {
        if key_pair.private.len() != 32 || key_pair.public.len() != 32 {
            return Err(KeyError("key data is malformed".into()));
        }
        #[cfg(feature = "ring")]
        {
            let signing_key = ring::signature::Ed25519KeyPair::from_seed_and_public_key(
                &key_pair.private,
                &key_pair.public,
            )?;
            let signing_key = Arc::new(signing_key);
            let verifying_key = ring::signature::UnparsedPublicKey::new(
                &ring::signature::ED25519,
                key_pair.public.clone(),
            );
            let verifying_key = Arc::new(verifying_key);
            todo!()
        }
        #[cfg(not(feature = "ring"))]
        {
            let key_pair_bytes = key_pair
                .concat()
                .try_into()
                .map_err(|_| KeyError("key data is malformed".into()))?;
            let result = ed25519_dalek::SigningKey::from_keypair_bytes(&key_pair_bytes)?;
            return Ok(result);
        }
    }
    fn verify(&self, data: &[u8]) -> Result<(), VerificationError> {
        todo!()
    }
}

#[cfg(feature = "ring")]
#[derive(Clone)]
struct Rsa {
    inner: Arc<ring::signature::RsaKeyPair>,
}
#[cfg(not(feature = "ring"))]
#[derive(Clone)]
enum Rsa {
    Ps256(rsa::pkcs1v15::SigningKey<sha2::Sha256>),
    Ps384(rsa::pkcs1v15::SigningKey<sha2::Sha384>),
    Ps512(rsa::pkcs1v15::SigningKey<sha2::Sha512>),
    Rs256(rsa::pss::SigningKey<sha2::Sha256>),
    Rs384(rsa::pss::SigningKey<sha2::Sha384>),
    Rs512(rsa::pss::SigningKey<sha2::Sha512>),
}

impl Rsa {
    fn from_key_pair(algorithm: Algorithm, keys: &KeyPair) -> Result<Self, KeyError> {
        todo!()
    }

    fn sign(&self, data: &[u8]) -> Result<Vec<u8>, KeyError> {
        #[cfg(feature = "ring")]
        {
            todo!()
        }
        #[cfg(not(feature = "ring"))]
        match self {
            Rsa::Ps256(key) => todo!(),
            Rsa::Ps384(key) => todo!(),
            Rsa::Ps512(key) => todo!(),
            Rsa::Rs256(key) => todo!(),
            Rsa::Rs384(key) => todo!(),
            Rsa::Rs512(key) => todo!(),
        }
    }

    fn verify(&self, data: &[u8]) -> Result<(), VerificationError> {
        todo!()
    }
}
