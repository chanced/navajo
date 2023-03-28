use crate::{
    b64,
    error::{KeyError, SignatureError},
    jose::{Algorithm as JwkAlgorithm, Jwk, KeyOperation, KeyUse},
    sensitive,
};
use alloc::sync::Arc;
use alloc::vec::Vec;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use generic_array::GenericArray;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use typenum::{U32, U48};

use super::{Algorithm, KeyPair, Signature};

#[derive(Clone, Serialize, Deserialize)]
#[serde(try_from = "Jwk", into = "Jwk")]
pub(crate) struct VerifyingKey {
    pub(super) pub_id: String,
    inner: Arc<Inner>,
    key: sensitive::Bytes,
    key_operations: Vec<KeyOperation>,
    key_use: Option<KeyUse>,
}

impl core::fmt::Debug for VerifyingKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("VerifyingKey")
            .field("key_id", &self.pub_id)
            .field("algorithm", &self.algorithm())
            .field("key_use", &self.key_use)
            .field("key_operations", &self.key_operations)
            .field("value", &URL_SAFE_NO_PAD.encode(self.key.as_ref()))
            .finish()
    }
}

impl VerifyingKey {
    pub fn verify(&self, msg: &[u8], signature: &Signature) -> Result<(), SignatureError> {
        self.inner.verify(msg, signature)
    }
    pub fn pub_id(&self) -> &str {
        &self.pub_id
    }
    pub fn key_use(&self) -> Option<&crate::jose::KeyUse> {
        self.key_use.as_ref()
    }
    pub fn key_operations(&self) -> &[crate::jose::KeyOperation] {
        &self.key_operations
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
        metadata: Option<Arc<Value>>,
    ) -> Result<Self, KeyError> {
        let inner = Arc::new(Inner::from_key_pair(algorithm, key_pair)?);
        let key = key_pair.public.clone();

        let key_operations: Vec<KeyOperation> = metadata
            .as_ref()
            .map(|v| {
                v.get("key_ops")
                    .and_then(|v| v.as_array())
                    .map(|v| {
                        v.iter()
                            .filter_map(|v| v.as_str())
                            .map(KeyOperation::from)
                            .collect::<Vec<_>>()
                    })
                    .unwrap_or_default()
            })
            .unwrap_or_default();
        let key_use =
            metadata.and_then(|v| v.get("use").and_then(|v| v.as_str()).map(KeyUse::from));

        Ok(Self {
            pub_id,
            inner,
            key,
            key_operations,
            key_use,
        })
    }

    pub fn bytes(&self) -> sensitive::Bytes {
        self.key.clone()
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

    fn verify(&self, data: &[u8], signature: &Signature) -> Result<(), SignatureError> {
        match self {
            Self::Ed25519(inner) => inner.verify(data, signature),
            Self::Ecdsa(inner) => inner.verify(data, signature),
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
    fn from_x_y(
        algorithm: Algorithm,
        x: Option<&[u8]>,
        y: Option<&[u8]>,
    ) -> Result<Self, KeyError> {
        let x = x.ok_or_else(|| "missing x")?;
        let y = y.ok_or_else(|| "missing y")?;
        match algorithm {
            Algorithm::Es256 => todo!(),
            Algorithm::Es384 => todo!(),
            Algorithm::Ed25519 => todo!(),
        }
    }

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

    fn verify(&self, msg: &[u8], sig: &Signature) -> Result<(), SignatureError> {
        #[cfg(feature = "ring")]
        {
            match self {
                Self::P256(key) => Ok(key.verify(msg, sig)?),
                Self::P384(key) => Ok(key.verify(msg, sig)?),
            }
        }
        #[cfg(not(feature = "ring"))]
        {
            match self {
                Self::P256(key) => {
                    use p256::ecdsa::{signature::Verifier, Signature as EcdsaSignature};

                    let sig: EcdsaSignature = EcdsaSignature::try_from(sig.as_ref())?;
                    Ok(key.verify(msg, &sig)?)
                }
                Self::P384(key) => {
                    use p384::ecdsa::{signature::Verifier, Signature as EcdsaSignature};

                    let sig: EcdsaSignature = EcdsaSignature::try_from(sig.as_ref())?;
                    Ok(key.verify(msg, &sig)?)
                }
            }
        }
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
            let key = ed25519_dalek::VerifyingKey::from_bytes(
                key_pair.public.as_ref().try_into().unwrap(),
            )?; // safety: len checked above
            Ok(Self(key))
        }
    }
    fn verify(&self, msg: &[u8], signature: &Signature) -> Result<(), SignatureError> {
        #[cfg(feature = "ring")]
        {
            self.0
                .verify(&msg, signature)
                .map_err(|_| SignatureError::Failure("".into()))
        }
        #[cfg(not(feature = "ring"))]
        {
            use ed25519_dalek::Verifier;
            let bytes: ed25519_dalek::Signature = msg
                .try_into()
                .map_err(|_| SignatureError::InvalidLen(msg.len()))?;

            let signature = ed25519_dalek::Signature::from_slice(msg)?;
            let result = self.0.verify(msg, &signature)?;
            Ok(result)
        }
    }
}

impl TryFrom<Jwk> for VerifyingKey {
    type Error = KeyError;

    fn try_from(jwk: Jwk) -> Result<Self, Self::Error> {
        Self::try_from(&jwk)
    }
}

impl TryFrom<&Jwk> for VerifyingKey {
    type Error = KeyError;
    fn try_from(jwk: &Jwk) -> Result<Self, Self::Error> {
        // let alg = jwk
        //     .algorithm()
        //     .ok_or("missing or undetectable algorithm".into())?;

        // match alg {
        //     JwkAlgorithm::Es256 => {
        //         let inner = Inner::Ecdsa(Ecdsa::P256(key.clone()));
        //         Ok(VerifyingKey {
        //             pub_id: jwk.key_id.unwrap_or_default(),
        //             inner: Arc::new(inner),
        //             key,
        //             key_operations: jwk.key_operations,
        //             key_use: jwk.key_use,
        //         })
        //     }
        //     JwkAlgorithm::Es384 => todo!(),
        //     JwkAlgorithm::EdDsa => todo!(),
        //     alg => Err(D::Error::custom(format!("unsupported algorithm: {alg}"))),
        // }
        todo!()
    }
}
