use serde::{Deserialize, Serialize};
use serde_json::Value;
use zeroize::ZeroizeOnDrop;

use crate::{
    error::{KeyError, MalformedError},
    rand::is_fully_repeating,
    sensitive, Rng, SystemRng,
};

use super::Algorithm;

#[derive(Serialize, Deserialize, Clone)]
struct KeyPair {
    #[serde(rename = "pvt")]
    private: sensitive::Bytes,
    #[serde(rename = "pub")]
    public: sensitive::Bytes,
}

#[derive(Clone)]
pub(crate) struct SigningKey {
    inner: Inner,
    key_pair: KeyPair,
    meta: Option<Value>,
}
impl SigningKey {
    pub fn new(algorithm: Algorithm, meta: Option<Value>) -> Self {
        Self::generate(&SystemRng, algorithm, meta)
    }

    fn generate<G>(rng: &G, algorithm: Algorithm, meta: Option<Value>) -> Self
    where
        G: Rng,
    {
        let key_pair = Inner::generate_key_pair(rng, algorithm);
        todo!()
        // Self { inner, bytes, meta }
    }
}

#[derive(Clone)]
enum Inner {
    Ed25519(Ed25519),
    Ecdsa(Ecdsa),
    Rsa(Rsa),
}

impl Inner {
    fn generate_key_pair(rng: &impl Rng, algorithm: Algorithm) -> KeyPair {
        match algorithm {
            Algorithm::Ed25519 => Ed25519::generate_key_pair(rng, algorithm),
            Algorithm::Es256 | Algorithm::Es384 => Ecdsa::generate_key_pair(rng, algorithm),
            Algorithm::Rs256
            | Algorithm::Rs384
            | Algorithm::Rs512
            | Algorithm::Ps256
            | Algorithm::Ps384
            | Algorithm::Ps512 => Rsa::generate_key_pair(rng, algorithm),
        }
    }

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
            | Algorithm::Ps512 => {
                // Self::RsaPss(RsaPss::from_pkcs8(algorithm, value.as_ref())?)
                todo!()
            }
        };
        Ok(key)
    }
}

#[cfg(feature = "ring")]
#[derive(Debug)]
struct Ecdsa {
    inner: ring::signature::EcdsaKeyPair,
}
#[cfg(not(feature = "ring"))]
#[derive(Clone)]
enum Ecdsa {
    P256(p256::ecdsa::SigningKey),
    P384(p384::ecdsa::SigningKey),
}

impl Ecdsa {
    fn generate_key_pair(rng: &impl Rng, algorithm: Algorithm) -> KeyPair {
        todo!()
    }
    fn from_key_pair(algorithm: Algorithm, keys: &KeyPair) -> Result<Self, KeyError> {
        #[cfg(feature = "ring")]
        {
            let inner = ring::signature::EcdsaKeyPair::from_pkcs8(
                algorithm.ring_ecdsa_signing_algorithm(),
                bytes,
            )?;
            Ok(Self { inner })
        }
        #[cfg(not(feature = "ring"))]
        {
            let signing_key = match algorithm {
                Algorithm::Es256 => {
                    // use p256::{ecdsa::SigningKey, pkcs8::DecodePrivateKey};
                    // let signing_key = SigningKey::from_bytes(&keys.private)?;
                    // Self::P256(signing_key)
                    todo!()
                }
                Algorithm::Es384 => {
                    // use p384::{ecdsa::SigningKey, pkcs8::DecodePrivateKey};
                    // let signing_key = SigningKey::from_pkcs8_der(bytes)?;
                    // Self::P384(signing_key)
                    todo!()
                }
                _ => unreachable!(),
            };
            Ok(signing_key)
        }
    }
}

#[cfg(feature = "ring")]
#[derive(Debug)]
struct Rsa {
    inner: ring::signature::RsaKeyPair,
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
    fn generate_key_pair(rng: &impl Rng, algorithm: Algorithm) -> KeyPair {
        todo!()
    }
}

#[derive(Clone)]
struct Ed25519 {
    #[cfg(feature = "ring")]
    inner: ring::signature::Ed25519KeyPair,
    #[cfg(not(feature = "ring"))]
    inner: ed25519_dalek::SigningKey,
}

impl Ed25519 {
    fn from_key_pair(_: Algorithm, key_pair: &KeyPair) -> Result<Self, KeyError> {
        if key_pair.private.len() != 32 || key_pair.public.len() != 32 {
            return Err(KeyError("key data is malformed".into()));
        }

        // let signing_key = ring::signature::Ed25519KeyPair::from_seed_and_public_key(
        //     &key_pair.private,
        //     &key_pair.public,
        // )?;
        // let result = ed25519_dalek::SigningKey::from_keypair_bytes(bytes.try_into()?)?;

        #[cfg(not(feature = "ring"))]
        {}
        todo!()
    }
    fn generate_key_pair(rng: &impl Rng, _: Algorithm) -> KeyPair {
        let mut bytes = [0u8; 32];
        while is_fully_repeating(&bytes) {
            rng.fill(&mut bytes)
                .expect("operating system failed to generate random number");
        }
        todo!()
    }

    fn validate_key(key: &[u8]) -> Result<(), KeyError> {
        if key.len() != 32 {
            return Err(KeyError("ed25519 private key must be 32 bytes".into()));
        }
        if is_fully_repeating(key) {
            return Err(KeyError(
                "private key may not contain fully repeating numbers".into(),
            ));
        }
        Ok(())
    }
}
