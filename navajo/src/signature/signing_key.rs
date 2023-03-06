use super::KeyPair;
use alloc::sync::Arc;
use rand_core::{CryptoRng, CryptoRngCore};
use serde_json::Value;

use crate::{error::KeyError, rand::is_zero, sensitive, Rng, SystemRng};

use super::Algorithm;

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

    pub fn sign(&self, data: &[u8]) -> Result<Vec<u8>, KeyError> {
        self.inner.sign(data)
    }

    pub fn new_with_rng<G>(rng: &G, algorithm: Algorithm, meta: Option<Value>) -> Self
    where
        G: Rng + CryptoRng + CryptoRngCore,
    {
        Self::generate(rng, algorithm, meta)
    }
    fn generate<G>(rng: &G, algorithm: Algorithm, meta: Option<Value>) -> Self
    where
        G: Rng + CryptoRng + CryptoRngCore,
    {
        let key_pair = Inner::generate_key_pair(rng, algorithm);
        let inner = Inner::from_key_pair(algorithm, &key_pair).unwrap();
        Self {
            key_pair,
            meta,
            inner,
        }
    }
}

#[derive(Clone)]
enum Inner {
    Ed25519(Ed25519),
    Ecdsa(Ecdsa),
    Rsa(Rsa),
}

impl Inner {
    fn generate_key_pair<G>(rng: &G, algorithm: Algorithm) -> KeyPair
    where
        G: Rng + CryptoRng + CryptoRngCore,
    {
        match algorithm {
            Algorithm::Ed25519 => Ed25519::generate_key_pair(rng, algorithm),
            Algorithm::Es256 | Algorithm::Es384 => Ecdsa::generate_key_pair(rng, algorithm),
            Algorithm::Rs256
            | Algorithm::Rs384
            | Algorithm::Rs512
            | Algorithm::Ps256
            | Algorithm::Ps384
            | Algorithm::Ps512 => Rsa::generate_key_pair(rng.clone(), algorithm),
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
            | Algorithm::Ps512 => Self::Rsa(Rsa::from_key_pair(algorithm, keys)?),
        };
        Ok(key)
    }

    fn sign(&self, data: &[u8]) -> Result<Vec<u8>, KeyError> {
        match self {
            Self::Ed25519(inner) => inner.sign(data),
            Self::Ecdsa(inner) => inner.sign(data),
            Self::Rsa(inner) => inner.sign(data),
        }
    }
}

#[cfg(feature = "ring")]
#[derive(Clone)]
struct Ecdsa {
    signing_key: Arc<ring::signature::EcdsaKeyPair>,
    verifying_key: Arc<ring::signature::UnparsedPublicKey<sensitive::Bytes>>,
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
    fn generate_key_pair<G>(rng: &G, algorithm: Algorithm) -> KeyPair
    where
        G: Rng,
    {
        match algorithm {
            Algorithm::Es256 => {
                let mut key = [0u8; 32];
                while is_zero(&key) {
                    rng.fill(&mut key).unwrap();
                }
                let signing_key = p256::ecdsa::SigningKey::from_bytes(&key).unwrap();
                let public_key = signing_key.verifying_key();
                let encoded_point = public_key.to_encoded_point(false);
                KeyPair {
                    private: sensitive::Bytes::new(&key),
                    public: sensitive::Bytes::new(encoded_point.as_bytes()),
                }
            }
            Algorithm::Es384 => {
                let mut key = [0u8; 32];
                while is_zero(&key) {
                    rng.fill(&mut key).unwrap();
                }
                let signing_key = p256::ecdsa::SigningKey::from_bytes(&key).unwrap();
                let public_key = signing_key.verifying_key();
                let encoded_point = public_key.to_encoded_point(false);
                KeyPair {
                    private: sensitive::Bytes::new(&key),
                    public: sensitive::Bytes::new(encoded_point.as_bytes()),
                }
            }
            _ => unreachable!(),
        }
    }
    fn from_key_pair(alg: Algorithm, keys: &KeyPair) -> Result<Self, KeyError> {
        #[cfg(feature = "ring")]
        {
            let signing_key = ring::signature::EcdsaKeyPair::from_private_key_and_public_key(
                alg.ring_ecdsa_signing_algorithm(),
                &keys.private,
                &keys.public,
            )?;
            let verifying_key = ring::signature::UnparsedPublicKey::new(
                alg.ring_ecdsa_verifying_algorithm(),
                keys.public.clone(),
            );
            let signing_key = Arc::new(signing_key);
            let verifying_key = Arc::new(verifying_key);
            return Ok(Self {
                signing_key,
                verifying_key,
            });
        }
        #[cfg(not(feature = "ring"))]
        {
            match alg {
                Algorithm::Es256 => {
                    use p256::ecdsa::SigningKey;
                    let signing_key = SigningKey::from_bytes(&keys.private)?;
                    Ok(Self::P256(signing_key))
                }
                Algorithm::Es384 => {
                    use p384::ecdsa::SigningKey;
                    let signing_key = SigningKey::from_bytes(&keys.private)?;
                    Ok(Self::P384(signing_key))
                }
                _ => unreachable!(),
            }
        }
    }

    fn sign(&self, data: &[u8]) -> Result<Vec<u8>, KeyError> {
        todo!()
    }
}

#[derive(Clone)]
struct Ed25519 {
    #[cfg(feature = "ring")]
    signing_key: Arc<ring::signature::Ed25519KeyPair>,
    #[cfg(feature = "ring")]
    verifying_key: Arc<ring::signature::UnparsedPublicKey<sensitive::Bytes>>,

    #[cfg(not(feature = "ring"))]
    signing_key: ed25519_dalek::SigningKey,
    #[cfg(not(feature = "ring"))]
    verifying_key: Arc<ed25519_dalek::VerifyingKey>,
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
            return Ok(Self {
                signing_key,
                verifying_key,
            });
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
    fn generate_key_pair(rng: &impl Rng, _: Algorithm) -> KeyPair {
        let mut bytes = [0u8; 32];
        while is_zero(&bytes) {
            rng.fill(&mut bytes)
                .expect("operating system failed to generate random number");
        }
        let signing_key = ed25519_dalek::SigningKey::from_bytes(&bytes);
        let verifying_key = signing_key.verifying_key();
        let public_key_bytes = verifying_key.to_bytes();
        KeyPair {
            private: sensitive::Bytes::new(&signing_key.to_bytes()),
            public: sensitive::Bytes::new(&public_key_bytes),
        }
    }

    fn sign(&self, data: &[u8]) -> Result<Vec<u8>, KeyError> {
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
    fn generate_key_pair<G>(mut rng: G, algorithm: Algorithm) -> KeyPair
    where
        G: Rng + CryptoRng + CryptoRngCore,
    {
        use rsa::pkcs8::{EncodePrivateKey, EncodePublicKey};

        let bits = 2048; // todo: consider making this configurable.

        // let bits = match algorithm {
        //     Algorithm::Ps256 | Algorithm::Rs256 => 2048,
        //     Algorithm::Ps384 | Algorithm::Rs384 => 3072,
        //     Algorithm::Ps512 | Algorithm::Rs512 => 4096,
        //     _ => unreachable!(),
        // };
        let private_key = rsa::RsaPrivateKey::new(&mut rng, bits).unwrap();
        let private = sensitive::Bytes::new(private_key.to_pkcs8_der().unwrap().as_bytes());
        let public_key = private_key.to_public_key();
        let public = sensitive::Bytes::new(public_key.to_public_key_der().unwrap().as_bytes());
        KeyPair { private, public }
    }
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
}

#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn test_generate() {
        let rng = crate::rand::SystemRng;
        let key = SigningKey::generate(&rng, Algorithm::Es256, None);
    }
}
