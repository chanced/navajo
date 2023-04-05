use crate::{
    error::{KeyError, SignatureError},
    jose::{Algorithm as JwkAlgorithm, Jwk},
    sensitive, Metadata,
};
use alloc::sync::Arc;

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use serde::{Deserialize, Serialize};

use super::{Algorithm, KeyPair};

#[derive(Clone, Deserialize)]
#[serde(try_from = "Jwk")]
pub(crate) struct VerifyingKey {
    pub(super) pub_id: String,
    inner: Arc<Inner>,
    key: sensitive::Bytes,
    jwk: Arc<Jwk>,
}

impl Serialize for VerifyingKey {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        self.jwk.serialize(serializer)
    }
}

impl PartialEq for VerifyingKey {
    fn eq(&self, other: &Self) -> bool {
        self.pub_id == other.pub_id
            && self.key == other.key
            && self.jwk.key_operations == other.jwk.key_operations
            && self.jwk.key_use == other.jwk.key_use
    }
}
impl core::fmt::Debug for VerifyingKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("VerifyingKey")
            .field("key_id", &self.pub_id)
            .field("algorithm", &self.algorithm())
            .field("key_use", &self.jwk.key_use)
            .field("key_operations", &self.jwk.key_operations)
            .field("value", &URL_SAFE_NO_PAD.encode(self.key.as_ref()))
            .finish()
    }
}

impl VerifyingKey {
    pub fn verify(&self, msg: &[u8], signature: &[u8]) -> Result<(), SignatureError> {
        self.inner.verify(msg, signature)
    }
    // pub fn pub_id(&self) -> &str {
    //     &self.pub_id
    // }
    // pub fn key_use(&self) -> Option<&crate::jose::KeyUse> {
    //     self.jwk.key_use.as_ref()
    // }
    // pub(crate) fn key_operations(&self) -> &[crate::jose::KeyOperation] {
    //     self.jwk.key_operations.as_ref()
    // }

    pub fn algorithm(&self) -> Algorithm {
        match self.inner.as_ref() {
            Inner::Ed25519(_) => Algorithm::Ed25519,
            Inner::Ecdsa(ecdsa) => match ecdsa {
                Ecdsa::P256(_) => Algorithm::Es256,
                Ecdsa::P384(_) => Algorithm::Es384,
            },
        }
    }

    pub fn jwk(&self) -> Arc<Jwk> {
        self.jwk.clone()
    }

    pub(super) fn from_material(
        algorithm: Algorithm,
        pub_id: String,
        key_pair: &KeyPair,
        metadata: Arc<Metadata>,
    ) -> Result<Self, KeyError> {
        let inner = Arc::new(Inner::from_key_pair(algorithm, key_pair)?);
        let key = key_pair.public.clone();
        let key_operations = metadata.key_operations().cloned().unwrap_or_default();
        let key_id = Some(pub_id.clone());
        let jwt_algorithm = algorithm.jwt_algorithm().into();
        let key_use = metadata.key_use().cloned();
        let _curve = algorithm.curve();
        let key_type = algorithm.key_type().into();

        let jwk = match algorithm {
            Algorithm::Es256 => Jwk {
                key_id,
                curve: algorithm.curve(),
                algorithm: jwt_algorithm,
                key_type,
                key_use,
                key_operations,
                x: Some(key[1..33].to_vec()),
                y: Some(key[33..65].to_vec()),
                ..Default::default()
            },

            Algorithm::Es384 => Jwk {
                key_id,
                curve: algorithm.curve(),
                algorithm: jwt_algorithm,
                key_type,
                key_use,
                key_operations,
                x: Some(key[1..49].to_vec()),
                y: Some(key[49..97].to_vec()),
                ..Default::default()
            },
            Algorithm::Ed25519 => Jwk {
                key_id,
                curve: algorithm.curve(),
                algorithm: jwt_algorithm,
                key_type,
                key_use,
                key_operations,
                x: Some(key.to_vec()),
                ..Default::default()
            },
        };
        let jwk = Arc::new(jwk);
        Ok(Self {
            pub_id,
            inner,
            key,
            jwk,
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

    fn verify(&self, data: &[u8], signature: &[u8]) -> Result<(), SignatureError> {
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
    fn from_bytes(algorithm: Algorithm, key: &[u8]) -> Result<Self, KeyError> {
        #[cfg(not(feature = "ring"))]
        match algorithm {
            Algorithm::Es256 => {
                if key.len() != 65 {
                    return Err(KeyError("key data is malformed".into()));
                }
                #[cfg(feature = "ring")]
                {
                    let key = ring::signature::UnparsedPublicKey::new(
                        algorithm.ring_ecdsa_verifying_algorithm(),
                        key,
                    );
                    Ok(Self::P256(key))
                }
                #[cfg(not(feature = "ring"))]
                {
                    let encoded_point = p256::EncodedPoint::from_bytes(key)
                        .map_err(|e| format!("key data is malformed: {e}"))?;
                    let key = p256::ecdsa::VerifyingKey::from_encoded_point(&encoded_point)?;
                    Ok(Self::P256(key))
                }
            }
            Algorithm::Es384 => {
                if key.len() != 97 {
                    return Err(KeyError("key data is malformed".into()));
                }
                let encoded_point = p384::EncodedPoint::from_bytes(key)
                    .map_err(|e| format!("key data is malformed: {e}"))?;
                let key = p384::ecdsa::VerifyingKey::from_encoded_point(&encoded_point)?;
                Ok(Self::P384(key))
            }
            _ => unreachable!(),
        }
    }

    fn from_key_pair(alg: Algorithm, keys: &KeyPair) -> Result<Self, KeyError> {
        Self::from_bytes(alg, keys.public.as_slice())
    }

    fn verify(&self, msg: &[u8], sig: &[u8]) -> Result<(), SignatureError> {
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

                    let sig: EcdsaSignature = EcdsaSignature::try_from(sig)?;
                    Ok(key.verify(msg, &sig)?)
                }
                Self::P384(key) => {
                    use p384::ecdsa::{signature::Verifier, Signature as EcdsaSignature};
                    let sig: EcdsaSignature = EcdsaSignature::try_from(sig)?;
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
    fn from_bytes(_: Algorithm, bytes: &[u8]) -> Result<Self, KeyError> {
        if bytes.len() != 32 {
            return Err(KeyError("key data is malformed".into()));
        }
        #[cfg(feature = "ring")]
        {
            let verifying_key = ring::signature::UnparsedPublicKey::new(
                &ring::signature::ED25519,
                key_pair.public.clone(),
            );
            let verifying_key = Arc::new(verifying_key);
            Ok(Self(verifying_key))
        }
        #[cfg(not(feature = "ring"))]
        {
            let key = ed25519_dalek::VerifyingKey::from_bytes(bytes.try_into().unwrap())?; // safety: len checked above
            Ok(Self(key))
        }
    }
    fn from_key_pair(alg: Algorithm, key_pair: &KeyPair) -> Result<Self, KeyError> {
        Self::from_bytes(alg, &key_pair.public)
    }
    fn verify(&self, msg: &[u8], signature: &[u8]) -> Result<(), SignatureError> {
        #[cfg(feature = "ring")]
        {
            self.0.verify(&msg, signature)?
        }
        #[cfg(not(feature = "ring"))]
        {
            use ed25519_dalek::Verifier;
            let signature = ed25519_dalek::Signature::from_slice(signature)?;

            Ok(self.0.verify(msg, &signature)?)
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
        let alg = jwk.algorithm().ok_or("missing or undetectable algorithm")?;
        let jwk = jwk.clone();
        let (key, inner) = match alg {
            JwkAlgorithm::Es256 => {
                let x = jwk.x.as_ref().ok_or("missing x")?;
                let y = jwk.y.as_ref().ok_or("missing y")?;
                let mut key = [x.as_slice(), y.as_slice()].concat();
                if key.len() == 64 {
                    key.splice(0..0, [4].iter().cloned());
                }
                let key = sensitive::Bytes::from(key);
                let ecdsa = Ecdsa::from_bytes(Algorithm::Es256, &key)?;
                (key, Arc::new(Inner::Ecdsa(ecdsa)))
            }
            JwkAlgorithm::Es384 => {
                let x = jwk.x.as_ref().ok_or("missing x")?;
                let y = jwk.y.as_ref().ok_or("missing y")?;
                let mut key = [x.as_slice(), y.as_slice()].concat();
                if key.len() == 96 {
                    key.splice(0..0, [4].iter().cloned());
                }
                let ecdsa = Ecdsa::from_bytes(Algorithm::Es384, &key)?;
                let key = sensitive::Bytes::from(key);
                (key, Arc::new(Inner::Ecdsa(ecdsa)))
            }
            JwkAlgorithm::EdDsa => {
                let x = jwk.x.as_ref().ok_or("missing x")?;
                let key = sensitive::Bytes::from(x.as_slice());
                let ed25519 = Ed25519::from_bytes(Algorithm::Ed25519, x.as_slice())?;
                (key, Arc::new(Inner::Ed25519(ed25519)))
            }
            alg => Err(KeyError(format!("unsupported algorithm: {alg}")))?,
        };
        let pub_id = jwk.key_id.clone().unwrap_or(Default::default());
        let jwk = Arc::new(jwk);
        Ok(Self {
            pub_id,
            inner,
            key,
            jwk,
        })
    }
}

#[cfg(test)]
mod tests {
    use strum::IntoEnumIterator;

    use crate::{dsa::signing_key::SigningKey, SystemRng};

    use super::*;

    #[test]
    fn test_serde() {
        for alg in Algorithm::iter() {
            let key = SigningKey::generate(
                &SystemRng,
                alg,
                "test+".to_string() + &alg.to_string().to_lowercase(),
                None,
            );
            let json = serde_json::to_string_pretty(&key.verifying_key).unwrap();
            let de_key = serde_json::from_str::<VerifyingKey>(&json).unwrap();
            assert_eq!(key.verifying_key, de_key);
        }
    }
}
