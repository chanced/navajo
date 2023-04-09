use core::str::FromStr;

use crate::{
    dsa::Signature,
    error::{DuplicatePubIdError, KeyNotFoundError, RemoveKeyError, SignatureError, TokenError},
    jose::{Header, Jwk, Jws, Validator, VerifiedJws},
};
use alloc::{
    borrow::{Cow, ToOwned},
    string::{String, ToString},
    sync::Arc,
};
use serde::{Deserialize, Serialize};

use super::{verifying_key::VerifyingKey, Algorithm};

#[cfg(feature = "std")]
type Map<K, V> = std::collections::HashMap<K, V>;
#[cfg(not(feature = "std"))]
type Map<K, V> = alloc::collections::BTreeMap<K, V>;

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
                .map(|k| k.jwk());
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

    pub fn verify_jws<'t>(
        &self,
        jws: &'t str,
        validator: &Validator,
    ) -> Result<VerifiedJws<'t>, TokenError> {
        let Jws {
            header,
            payload,
            signature,
        } = Jws::from_str(jws)?;
        let header: Header = serde_json::from_slice(&header)?;
        let jwk = self.verify(header.key_id.as_deref(), &payload, &signature)?;
        let claims = serde_json::from_slice(&payload)?;
        validator.validate(&claims)?;
        let algorithm = jwk.dsa_algorithm().unwrap(); // safety: if the token can be validated, the algorithm is known.
        let signature = Signature::new(algorithm, &signature)?;

        Ok(VerifiedJws::new(
            header,
            claims,
            signature,
            Cow::Borrowed(jws),
            jwk,
        ))
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

    pub(crate) fn add(&mut self, key: VerifyingKey) -> Result<(), DuplicatePubIdError> {
        if self.keys.contains_key(&key.pub_id) {
            Err(DuplicatePubIdError(key.pub_id))
        } else {
            let mut map: Map<String, VerifyingKey> = self.keys.as_ref().to_owned();
            map.insert(key.pub_id.clone(), key);
            self.keys = Arc::new(map);
            Ok(())
        }
    }

    pub(crate) fn delete(&mut self, pub_id: &str) -> Result<Jwk, RemoveKeyError<Algorithm>> {
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
    use crate::{
        dsa::*,
        jose::{Claims, NumericDate, Validator},
    };
    use alloc::string::ToString;
    use strum::IntoEnumIterator;

    const NOW: NumericDate = NumericDate(1680495923);

    #[test]
    fn test_verify() {
        let msg = b"data to sign";
        for alg in Algorithm::iter() {
            let mut signer = Signer::new(alg, None, None);
            let first_sig = signer.sign(msg);
            let first_key_id = signer.primary_key_id().to_string();
            let second = signer.add(Algorithm::Ed25519, None, None).unwrap();
            signer.promote(second.id).unwrap();
            let other_signer = Signer::new(alg, None, None);

            let sig = signer.sign(msg);
            let invalid_sig = other_signer.sign(msg);

            let verifier = signer.verifier();
            assert!(verifier.verify(None, msg, &sig).is_ok());
            assert!(verifier.verify(Some(&second.pub_id), msg, &sig).is_ok());
            assert!(verifier
                .verify(Some(&first_key_id), msg, &first_sig)
                .is_ok());
            assert!(verifier.verify(None, msg, &invalid_sig).is_err());
        }
    }

    // {"alg":"ES256","kid":"1865549783"}
    // {"alg":"ES384","kid":"3656448661"}
    #[test]
    fn test_verify_jws() {
        let claims = Claims::builder()
            .expiration_time(NOW + 100)
            .issuer("https://example.com")
            .audience("test")
            .build()
            .unwrap();

        let validator = Validator::builder()
            .expected_issuer("https://example.com".into())
            .expected_audience("test".into())
            .now_timestamp(NOW)
            .clock_skew(core::time::Duration::from_secs(0))
            .build()
            .unwrap();

        for alg in Algorithm::iter() {
            let mut signer = Signer::new(alg, None, None);
            let jws = signer.sign_jws(claims.clone()).unwrap();

            let verifier = signer.verifier();
            let verified_jws = verifier.verify_jws(jws.token(), &validator).unwrap();

            // println!("{verified_jws}");
            assert_eq!(&jws, &verified_jws);

            assert_eq!(
                verified_jws.header().key_id,
                Some(signer.primary_key_id().to_string())
            );

            assert_eq!(&claims, verified_jws.claims());

            let second = signer.add(Algorithm::Ed25519, None, None).unwrap();

            signer.promote(second.id).unwrap();
            let other_signer = Signer::new(alg, None, None);

            let jws = signer.sign_jws(claims.clone()).unwrap();
            let invalid_jws = other_signer.sign_jws(claims.clone()).unwrap();

            let verifier = signer.verifier();
            let verified_jws = verifier.verify_jws(jws.token(), &validator).unwrap();

            assert_eq!(
                verified_jws.header().key_id,
                Some(signer.primary_key_id().to_string())
            );

            assert!(verifier
                .verify_jws(invalid_jws.token(), &validator)
                .is_err());
        }
    }
}
