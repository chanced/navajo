use crate::{
    error::MalformedError,
    jose::{Claims, Header, Jws, VerifiedJws},
    Metadata,
};
use core::fmt::Debug;

use super::{verifying_key::VerifyingKey, KeyPair, Signature};
use alloc::{
    borrow::Cow,
    string::{String, ToString},
    sync::Arc,
};
use serde::{Deserialize, Serialize};
use zeroize::ZeroizeOnDrop;

use crate::{
    error::KeyError,
    key::{Key, KeyMaterial},
    primitive::Kind,
    rand::is_zero,
    sensitive, Rng,
};

use super::Algorithm;

#[derive(Clone, ZeroizeOnDrop, Serialize)]
pub(crate) struct SigningKey {
    #[serde(rename = "value")]
    key_pair: KeyPair,
    #[zeroize(skip)]
    #[serde(rename = "alg")]
    algorithm: Algorithm,
    #[zeroize(skip)]
    #[serde(skip_serializing)]
    inner: Arc<Inner>,
    #[zeroize(skip)]
    #[serde(skip_serializing)]
    pub(super) verifying_key: VerifyingKey,
    #[zeroize(skip)]
    pub_id: String,
}

impl Key<SigningKey> {
    pub(crate) fn pub_id(&self) -> &str {
        &self.material().pub_id
    }

    pub(crate) fn verifying_key(&self) -> VerifyingKey {
        self.material().verifying_key.clone()
    }

    pub(crate) fn sign(&self, data: &[u8]) -> Signature {
        self.material().sign(data)
    }
    fn header(&self) -> Header {
        Header {
            algorithm: self.algorithm().jwt_algorithm(),
            key_id: Some(self.material().pub_id.clone()),
            content_type: None,
            token_type: None,
            jwk: None,
            jwks_url: None,
            x509_cert_chain: None,
            x509_cert_sha1_thumbprint: None,
            x509_cert_sha256_thumbprint: None,
            x509_url: None,
            critical: Default::default(),
            encryption: None,
            zip: None,
            iv: None,
            additional_fields: Default::default(),
        }
    }
    pub(crate) fn sign_jws<'c>(&self, claims: Claims) -> Result<VerifiedJws<'c>, MalformedError> {
        let claims_json = serde_json::to_vec(&claims)?;
        let signature = self.sign(&claims_json);

        let header = self.header();

        let header_json = serde_json::to_vec(&header)?;
        let token = Jws {
            header: header_json,
            payload: claims_json,
            signature: &signature,
        }
        .to_string();

        Ok(VerifiedJws::new(
            header,
            claims,
            signature,
            Cow::Owned(token),
            self.verifying_key().jwk(),
        ))
    }
}

impl SigningKey {
    pub fn sign(&self, data: &[u8]) -> Signature {
        self.inner.sign(data)
    }
    #[cfg(test)]
    #[allow(dead_code)]
    pub fn new_with_rng<N>(
        rng: &N,
        algorithm: Algorithm,
        pub_id: String,
        metadata: Option<Metadata>,
    ) -> Self
    where
        N: Rng,
    {
        Self::generate(rng, algorithm, pub_id, metadata)
    }

    fn from_material(
        algorithm: Algorithm,
        pub_id: String,
        key_pair: KeyPair,
        metadata: Metadata,
    ) -> Result<Self, KeyError> {
        let inner = Arc::new(Inner::from_key_pair(algorithm, &key_pair)?);
        let verifying_key =
            VerifyingKey::from_material(algorithm, pub_id.clone(), &key_pair, metadata)?;
        Ok(Self {
            key_pair,
            pub_id,
            inner,
            algorithm,
            verifying_key,
        })
    }

    pub(super) fn generate<N>(
        rng: &N,
        algorithm: Algorithm,
        pub_id: String,
        metadata: Option<Metadata>,
    ) -> Self
    where
        N: Rng,
    {
        let key_pair = Inner::generate_key_pair(rng, algorithm);
        let inner = Arc::new(Inner::from_key_pair(algorithm, &key_pair).unwrap());
        let verifying_key = VerifyingKey::from_material(
            algorithm,
            pub_id.clone(),
            &key_pair,
            metadata.unwrap_or_default(),
        )
        .unwrap();
        Self {
            key_pair,
            inner,
            algorithm,
            verifying_key,
            pub_id,
        }
    }
}

impl<'de> Deserialize<'de> for SigningKey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct SerializedKey {
            value: KeyPair,
            alg: Algorithm,
            pub_id: String,
            #[serde(default)]
            metadata: Metadata,
        }
        let SerializedKey {
            value: key_pair,
            alg,
            pub_id,
            metadata,
        } = Deserialize::deserialize(deserializer)?;

        Self::from_material(alg, pub_id, key_pair, metadata).map_err(serde::de::Error::custom)
    }
}

impl Debug for SigningKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("SigningKey")
            .field("algorithm", &self.algorithm)
            .field("key_pair", &self.key_pair)
            .finish()
    }
}

impl PartialEq for SigningKey {
    fn eq(&self, other: &Self) -> bool {
        self.key_pair == other.key_pair && self.algorithm == other.algorithm
    }
}
impl Eq for SigningKey {}
impl KeyMaterial for SigningKey {
    type Algorithm = Algorithm;

    fn algorithm(&self) -> Self::Algorithm {
        self.algorithm
    }
    fn kind() -> crate::primitive::Kind {
        Kind::Dsa
    }
}

enum Inner {
    Ed25519(Ed25519),
    Ecdsa(Ecdsa),
    // Rsa(Rsa),
}
impl Debug for Inner {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Inner::Ed25519(_) => write!(f, "Ed25519"),
            Inner::Ecdsa(_) => write!(f, "Ecdsa"),
        }
    }
}
impl Inner {
    fn generate_key_pair<N>(rng: &N, algorithm: Algorithm) -> KeyPair
    where
        N: Rng,
    {
        match algorithm {
            Algorithm::Ed25519 => Ed25519::generate_key_pair(rng, algorithm),
            Algorithm::Es256 | Algorithm::Es384 => Ecdsa::generate_key_pair(rng, algorithm),
        }
    }

    fn from_key_pair(algorithm: Algorithm, keys: &KeyPair) -> Result<Self, KeyError> {
        let key = match algorithm {
            Algorithm::Ed25519 => Self::Ed25519(Ed25519::from_key_pair(algorithm, keys)?),
            Algorithm::Es256 | Algorithm::Es384 => {
                Self::Ecdsa(Ecdsa::from_key_pair(algorithm, keys)?)
            }
        };
        Ok(key)
    }

    fn sign(&self, data: &[u8]) -> Signature {
        match self {
            Self::Ed25519(inner) => inner.sign(data),
            Self::Ecdsa(inner) => inner.sign(data),
        }
    }
}

#[cfg(feature = "ring")]
enum Ecdsa {
    P256(ring::signature::EcdsaKeyPair),
    P384(ring::signature::EcdsaKeyPair),
}

#[cfg(not(feature = "ring"))]
enum Ecdsa {
    P256(p256::ecdsa::SigningKey),
    P384(p384::ecdsa::SigningKey),
}
impl Ecdsa {
    fn generate_key_pair<N>(rng: &N, algorithm: Algorithm) -> KeyPair
    where
        N: Rng,
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
                let encoded_point_bytes = encoded_point.as_bytes();
                KeyPair {
                    private: sensitive::Bytes::new(&key),
                    public: sensitive::Bytes::new(encoded_point_bytes),
                }
            }
            Algorithm::Es384 => {
                let mut key = [0u8; 48];
                while is_zero(&key) {
                    rng.fill(&mut key).unwrap();
                }
                let signing_key = p384::ecdsa::SigningKey::from_bytes(&key).unwrap();
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
            match alg {
                Algorithm::Es256 => Ok(Self::P256(signing_key)),
                Algorithm::Es384 => Ok(Self::P384(signing_key)),
                _ => unreachable!(),
            }
        }
        #[cfg(not(feature = "ring"))]
        {
            match alg {
                Algorithm::Es256 => Ok(Self::P256(p256::ecdsa::SigningKey::from_bytes(
                    &keys.private,
                )?)),
                Algorithm::Es384 => Ok(Self::P384(p384::ecdsa::SigningKey::from_bytes(
                    &keys.private,
                )?)),
                _ => unreachable!(),
            }
        }
    }

    fn sign(&self, data: &[u8]) -> Signature {
        #[cfg(feature = "ring")]
        {
            match self {
                Ecdsa::P256(key) => {
                    let sig = key.sign(&ring::rand::SystemRandom::new(), data).unwrap(); // this will only fail if ring's RNG fails
                    super::Signature::P256(sig.as_ref().try_into().unwrap())
                }
                Ecdsa::P384(key) => {
                    let sig = key.sign(&ring::rand::SystemRandom::new(), data).unwrap(); // this will only fail if ring's RNG fails
                    super::Signature::P384(sig.as_ref().try_into().unwrap())
                }
            }
        }
        #[cfg(not(feature = "ring"))]
        {
            match self {
                Ecdsa::P256(key) => {
                    use p256::ecdsa::{signature::Signer, Signature};
                    let sig: Signature = key.sign(data);
                    sig.into()
                }
                Ecdsa::P384(key) => {
                    use p384::ecdsa::{signature::Signer, Signature};
                    let sig: Signature = key.sign(data);
                    sig.into()
                }
            }
        }
    }
}

#[cfg(feature = "ring")]
struct Ed25519(ring::signature::Ed25519KeyPair);

#[cfg(not(feature = "ring"))]
struct Ed25519(ed25519_dalek::SigningKey);

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
            Ok(Self(signing_key))
        }
        #[cfg(not(feature = "ring"))]
        {
            let key_pair_bytes = key_pair
                .concat()
                .try_into()
                .map_err(|_| KeyError("key data is malformed".into()))?;
            let signing_key = ed25519_dalek::SigningKey::from_keypair_bytes(&key_pair_bytes)?;
            Ok(Self(signing_key))
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
    /// Signs the given message with the primary key and returns the digital [`Signature`].
    fn sign(&self, msg: &[u8]) -> Signature {
        #[cfg(feature = "ring")]
        {
            let signature = self.0.sign(msg);
            super::Signature::Ed25519(signature.as_ref().try_into().unwrap())
        }
        #[cfg(not(feature = "ring"))]
        {
            use ed25519_dalek::Signer;
            let signature = self.0.sign(msg);
            signature.into()
        }
    }
}

#[cfg(test)]
mod tests {

    use alloc::string::String;

    use crate::SystemRng;

    use super::*;
    #[derive(Debug, Clone, Serialize, Deserialize)]
    struct Payload {
        sub: String,
        aud: String,
    }

    // #[test]
    // fn test_generate() {
    //     let rng = crate::rand::SystemRng;
    //     let k = SigningKey::generate(&rng, Algorithm::Es384, "test".to_string(), None);

    //     let k = SigningKey::generate(&rng, Algorithm::Es256, "test".to_string(), None);
    //     let pk = k.key_pair.public.as_ref();

    //     let key = Key::new(3423, Status::Primary, Origin::Navajo, k, None);
    //     let claims = Claims::builder()
    //         .subject("test")
    //         .audience("test")
    //         .build()
    //         .unwrap();

    //     let jwt = key.sign_jws(claims).unwrap();
    //     // println!("{jwt}");
    // }
    #[test]
    fn test_sign() {
        // let ed25519 = SigningKey::generate(&SystemRng, Algorithm::Ed25519, "222".to_string(), None);
        let p256 = SigningKey::generate(&SystemRng, Algorithm::Es256, "222".to_string(), None);
        let p384 = SigningKey::generate(&SystemRng, Algorithm::Es384, "222".to_string(), None);

        // let ed25519_sig = ed25519.sign("test".as_bytes());

        let p256_sig = p256.sign("test".as_bytes());
        _ = p256_sig;
        let p384_sig = p384.sign("test".as_bytes());
        _ = p384_sig;
    }
}
