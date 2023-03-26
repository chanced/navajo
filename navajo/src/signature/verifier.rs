use alloc::sync::Arc;
use serde::{Deserialize, Serialize};

use crate::{
    error::{DuplicatePubIdError, RemoveKeyError},
    jose::Jwk,
};

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

    pub(crate) fn remove(&self, pub_id: &str) -> Result<Jwk, RemoveKeyError<Algorithm>> {
        todo!()
    }
}
