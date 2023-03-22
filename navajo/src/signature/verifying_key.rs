use alloc::{borrow::Cow, sync::Arc};
use base64::{engine::general_purpose as b64, Engine as _};
use ed25519_dalek::ed25519::SignatureBytes;
use p256::pkcs8::DecodePublicKey;
use serde::{Deserialize, Serialize};

use crate::{
    error::{KeyError, VerificationError},
    jwk::Jwk,
    sensitive,
};

use super::{Algorithm, KeyPair};

#[derive(Clone)]
pub(crate) struct VerifyingKey {
    pub_id: String,
    inner: Arc<Inner>,
    key: sensitive::Bytes,
}
impl<'de> Deserialize<'de> for VerifyingKey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        todo!()
    }
}
impl Serialize for VerifyingKey {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let alg = self.algorithm();
        let jwk = match self.inner.as_ref() {
            Inner::Ed25519(_) => {
                let x = b64::URL_SAFE_NO_PAD.encode(self.key.as_ref());
                Jwk {
                    key_id: Some(self.pub_id.clone()),
                    key_use: Some(Cow::Borrowed("sig")),
                    key_type: alg.key_type().into(),
                    algorithm: alg.jwt_algorithm().into(),
                    curve: alg.curve().map(Into::into),
                    x: Some(x.into()),
                    ..Default::default()
                }
            }
            Inner::Ecdsa(ecdsa) => match ecdsa {
                Ecdsa::P256(_) => Default::default(),
                Ecdsa::P384(_) => Default::default(),
            },
        };
        todo!()
    }
}

impl VerifyingKey {
    pub fn verify(&self, sig: &[u8]) -> Result<(), VerificationError> {
        self.inner.verify(sig)
    }
    pub fn algorithm(&self) -> Algorithm {
        match self.inner.as_ref() {
            Inner::Ed25519(_) => Algorithm::Ed25519,
            Inner::Ecdsa(ecdsa) => match ecdsa {
                Ecdsa::P256(_) => Algorithm::Es256,
                Ecdsa::P384(_) => Algorithm::Es384,
            },
        }
    }
    pub(super) fn from_material(
        algorithm: Algorithm,
        pub_id: String,
        key_pair: &KeyPair,
    ) -> Result<Self, KeyError> {
        let inner = Arc::new(Inner::from_key_pair(algorithm, key_pair)?);
        let key = key_pair.public.clone();
        Ok(Self { pub_id, inner, key })
    }
}

enum Inner {
    Ed25519(Ed25519),
    Ecdsa(Ecdsa),
    // Rsa(Rsa),
}

impl Inner {
    fn from_key_pair(algorithm: Algorithm, keys: &KeyPair) -> Result<Self, KeyError> {
        let key = match algorithm {
            Algorithm::Ed25519 => Self::Ed25519(Ed25519::from_key_pair(algorithm, keys)?),
            Algorithm::Es256 | Algorithm::Es384 => {
                Self::Ecdsa(Ecdsa::from_key_pair(algorithm, keys)?)
            }
        };
        Ok(key)
    }

    fn verify(&self, data: &[u8]) -> Result<(), VerificationError> {
        match self {
            Self::Ed25519(inner) => inner.verify(data),
            Self::Ecdsa(inner) => inner.verify(data),
            // Self::Rsa(inner) => inner.verify(data),
        }
    }
}

#[cfg(feature = "ring")]
enum Ecdsa {
    P256(ring::signature::UnparsedPublicKey<sensitive::Bytes>),
    P384(ring::signature::UnparsedPublicKey<sensitive::Bytes>),
}

#[cfg(not(feature = "ring"))]
enum Ecdsa {
    P256(p256::ecdsa::VerifyingKey),
    P384(p384::ecdsa::VerifyingKey),
}

impl Ecdsa {
    fn from_key_pair(alg: Algorithm, keys: &KeyPair) -> Result<Self, KeyError> {
        #[cfg(feature = "ring")]
        {
            // TODO: validate the input
            let key = ring::signature::UnparsedPublicKey::new(
                alg.ring_ecdsa_verifying_algorithm(),
                keys.public.clone(),
            );
            match alg {
                Algorithm::Es256 => Ok(Self::P256(key)),
                Algorithm::Es384 => Ok(Self::P384(key)),
                _ => unreachable!(),
            }
        }
        #[cfg(not(feature = "ring"))]
        {
            match alg {
                Algorithm::Es256 => {
                    let encoded_point = p256::EncodedPoint::from_bytes(&keys.public)
                        .map_err(|_| KeyError("key data is malformed".into()))?;
                    let key = p256::ecdsa::VerifyingKey::from_encoded_point(&encoded_point)?;
                    Ok(Self::P256(key))
                }
                Algorithm::Es384 => {
                    let encoded_point = p384::EncodedPoint::from_bytes(&keys.public)
                        .map_err(|_| KeyError("key data is malformed".into()))?;
                    let key = p384::ecdsa::VerifyingKey::from_encoded_point(&encoded_point)?;
                    Ok(Self::P384(key))
                }
                _ => unreachable!(),
            }
        }
    }

    fn verify(&self, _data: &[u8]) -> Result<(), VerificationError> {
        todo!()
    }
}
#[cfg(feature = "ring")]
struct Ed25519(ring::signature::UnparsedPublicKey<sensitive::Bytes>);
#[cfg(not(feature = "ring"))]
struct Ed25519(ed25519_dalek::VerifyingKey);

impl Ed25519 {
    fn from_key_pair(alg: Algorithm, key_pair: &KeyPair) -> Result<Self, KeyError> {
        if key_pair.public.len() != 32 {
            return Err(KeyError("key data is malformed".into()));
        }
        #[cfg(feature = "ring")]
        {
            let signing_key = ring::signature::Ed25519KeyPair::from_seed_and_public_key(
                &key_pair.private,
                &key_pair.public,
            )?;
            let _signing_key = Arc::new(signing_key);
            let verifying_key = ring::signature::UnparsedPublicKey::new(
                &ring::signature::ED25519,
                key_pair.public.clone(),
            );
            let _verifying_key = Arc::new(verifying_key);
            todo!()
        }
        #[cfg(not(feature = "ring"))]
        {
            let key = ed25519_dalek::VerifyingKey::from_bytes(
                key_pair.public.as_ref().try_into().unwrap(),
            )?; // safety: len checked above
            Ok(Self(key))
        }
    }
    fn verify(&self, data: &[u8]) -> Result<(), VerificationError> {
        use ed25519_dalek::Verifier;
        let bytes: ed25519_dalek::Signature = data
            .try_into()
            .map_err(|e| VerificationError("invalid length".to_string()))?;

        let signature = ed25519_dalek::Signature::from_slice(data);

        todo!()
    }
}
