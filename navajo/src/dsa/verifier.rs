use crate::{
    error::{DuplicatePubIdError, JwsError, KeyNotFoundError, RemoveKeyError, SignatureError},
    jose::{Claims, Header, Jwk, Jws},
};
use alloc::sync::Arc;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use super::{verifying_key::VerifyingKey, Algorithm};

#[cfg(feature = "std")]
type Map<K, V> = std::collections::HashMap<K, V>;
#[cfg(not(feature = "std"))]
type Map<k, V> = alloc::collections::BTreeMap<K, V>;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Verifier {
    keys: Arc<Map<String, super::VerifyingKey>>,
}
impl Verifier {
    pub fn verify(
        &self,
        id: Option<&str>,
        msg: &[u8],
        sig: &super::Signature,
    ) -> Result<(), SignatureError> {
        if let Some(id) = id {
            if let Some(key) = self.keys.get(id) {
                return key.verify(msg, sig);
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
                .map(|_| ());
        }
        #[cfg(not(feature = "rayon"))]
        {
            self.keys
                .values()
                .find_any(|k| k.verify(msg, sig).is_ok())
                .ok_or(SignatureError::Failure("failed to verify signature".into()))?;
        }
    }
    pub fn verify_jws<C, S>(&self, ctx: &C::Context, jws: &str) -> Result<C, JwsError<C>>
    where
        C: Claims,
    {
        let jws = jws.as_ref();
        let (header, payload, sig) = Jws::from_str(jws);
        let header: Header = serde_json::from_str(header)?;
        let payload: Value = serde_json::from_str(payload)?;
        C::validate(ctx, &header, &payload).map_err(JwsError::Validation)?;
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
        Ok(k.into())
    }
}

#[cfg(test)]
mod tests {
    use strum::IntoEnumIterator;

    use crate::dsa::*;
    #[test]
    fn test_verify() {
        let msg = b"data to sign";
        for alg in Algorithm::iter() {
            let mut signer = Signer::new(alg, None, None);
            let first_sig = signer.sign(msg);
            let first_key_id = signer.primary_key_id().to_string();
            let second = signer.add_key(Algorithm::Ed25519, None, None).unwrap();
            signer.promote_key(second.id).unwrap();
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
}
