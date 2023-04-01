use super::{DsaKeyInfo, Validate};

use crate::{
    error::{DuplicatePubIdError, JwsError, KeyNotFoundError, RemoveKeyError, SignatureError},
    jose::{decode_jws, Header, Jwk},
};
use alloc::sync::Arc;
use serde::{de::DeserializeOwned, Deserialize, Serialize};

use super::{verifying_key::VerifyingKey, Algorithm};

#[cfg(feature = "std")]
type Map<K, V> = std::collections::HashMap<K, V>;
#[cfg(not(feature = "std"))]
type Map<k, V> = alloc::collections::BTreeMap<K, V>;

pub trait Context {}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Verifier {
    keys: Arc<Map<String, super::VerifyingKey>>,
}
impl Verifier {
    pub fn verify(
        &self,
        id: Option<&str>,
        msg: &[u8],
        sig: &[u8],
    ) -> Result<Arc<Jwk>, SignatureError> {
        if let Some(id) = id {
            if let Some(key) = self.keys.get(id) {
                match key.verify(msg, sig) {
                    Ok(_) => return Ok(key.jwk()),
                    Err(e) => return Err(e),
                }
            } else {
                return Err(SignatureError::KeyNotFound(id.to_string()));
            }
        }
        #[cfg(feature = "rayon")]
        {
            use rayon::iter::ParallelBridge;
            use rayon::prelude::*;
            return self
                .keys
                .values()
                .par_bridge()
                .find_any(|k| k.verify(msg, sig).is_ok())
                .ok_or(SignatureError::Failure("failed to verify signature".into()))
                .map(|k| k.clone().into());
        }
        #[cfg(not(feature = "rayon"))]
        {
            return self
                .keys
                .values()
                .find(|k| k.verify(msg, sig).is_ok())
                .map(|k| k.jwk())
                .ok_or(SignatureError::Failure("failed to verify signature".into()));
        }
    }

    pub fn verify_jws<P>(&self, jws: &str) -> Result<(P, Header), JwsError<P>>
    where
        P: Validate + core::fmt::Debug + Clone + Serialize + DeserializeOwned,
    {
        let (header, payload, sig) = decode_jws::<P>(jws)?;
        self.verify(header.key_id.as_deref(), &payload, &sig)?;
        let payload: P = serde_json::from_slice(&payload)?;
        payload.validate().map_err(|e| JwsError::Validation(e))?;
        Ok((payload, header))
    }

    pub(crate) fn from_keyring(
        keyring: crate::keyring::Keyring<super::signing_key::SigningKey>,
    ) -> Self {
        let keys = keyring
            .keys()
            .iter()
            .map(|key| (key.pub_id().to_string(), key.verifying_key()))
            .collect();
        Self {
            keys: Arc::new(keys),
        }
    }

    pub(crate) fn add_key(&mut self, key: VerifyingKey) -> Result<(), DuplicatePubIdError> {
        if self.keys.contains_key(&key.pub_id) {
            Err(DuplicatePubIdError(key.pub_id))
        } else {
            let mut map: Map<String, VerifyingKey> = self.keys.as_ref().to_owned();
            map.insert(key.pub_id.clone(), key);
            self.keys = Arc::new(map);
            Ok(())
        }
    }

    pub(crate) fn remove(&mut self, pub_id: &str) -> Result<Jwk, RemoveKeyError<Algorithm>> {
        let k = self
            .keys
            .get(pub_id)
            .ok_or(KeyNotFoundError::PubId(pub_id.to_string()))?
            .clone();
        let keys: Map<String, VerifyingKey> = self
            .keys
            .iter()
            .filter(|(id, _)| id.as_str() != pub_id)
            .map(|(id, key)| (id.to_string(), key.clone()))
            .collect();
        self.keys = Arc::new(keys);
        Ok(k.jwk().as_ref().clone())
    }
}

#[cfg(test)]
mod tests {
    use serde::{Deserialize, Serialize};
    use strum::IntoEnumIterator;

    // #[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
    // struct Payload {
    //     exp: u64,
    //     iss: String,
    // }
    // impl Validate for Payload {
    //     type Error = String;

    //     fn validate(&self) -> Result<(), Self::Error> {
    //         if self.iss.as_str() != ctx.as_str() {
    //             return Err("invalid issuer".into());
    //         }
    //         Ok(())
    //     }
    // }

    // use crate::dsa::*;
    // #[test]
    // fn test_verify() {
    //     let msg = b"data to sign";
    //     for alg in Algorithm::iter() {
    //         let mut signer = Signer::new(alg, None, None);
    //         let first_sig = signer.sign(msg);
    //         let first_key_id = signer.primary_key_id().to_string();
    //         let second = signer.add_key(Algorithm::Ed25519, None, None).unwrap();
    //         signer.promote(second.id).unwrap();
    //         let other_signer = Signer::new(alg, None, None);

    //         let sig = signer.sign(msg);
    //         let invalid_sig = other_signer.sign(msg);

    //         let verifier = signer.verifier();
    //         assert!(verifier.verify(None, msg, &sig).is_ok());
    //         assert!(verifier.verify(Some(&second.pub_id), msg, &sig).is_ok());
    //         assert!(verifier
    //             .verify(Some(&first_key_id), msg, &first_sig)
    //             .is_ok());
    //         assert!(verifier.verify(None, msg, &invalid_sig).is_err());
    //     }
    // }
    // #[test]
    // fn test_verify_jws() {
    //     let payload = Payload {
    //         exp: 100_000,
    //         iss: "test".into(),
    //     };

    //     for alg in Algorithm::iter() {
    //         let mut signer = Signer::new(alg, None, None);
    //         let jws = signer.sign_jws(&payload).unwrap();

    //         let verifier = signer.verifier();
    //         let (res, header) = verifier
    //             .verify_jws::<Payload>(&"test".to_string(), &jws)
    //             .unwrap();

    //         assert_eq!(header.key_id, Some(signer.primary_key_id().to_string()));
    //         assert_eq!(res, payload.clone());

    //         assert!(verifier
    //             .verify_jws::<Payload>(&"expect failure".to_string(), &jws)
    //             .is_err());

    //         let second = signer.add_key(Algorithm::Ed25519, None, None).unwrap();

    //         signer.promote(second.id).unwrap();
    //         let other_signer = Signer::new(alg, None, None);

    //         let jws = signer.sign_jws(&payload).unwrap();
    //         let invalid_jws = other_signer.sign_jws(&payload).unwrap();

    //         let verifier = signer.verifier();
    //         let (res, header) = verifier
    //             .verify_jws::<Payload>(&"test".to_string(), &jws)
    //             .unwrap();
    //         assert_eq!(res, payload.clone());
    //         assert_eq!(header.key_id, Some(signer.primary_key_id().to_string()));

    //         assert!(verifier
    //             .verify_jws::<Payload>(&"test".to_string(), &invalid_jws)
    //             .is_err());
    //     }
    // }
}
