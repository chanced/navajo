use super::Algorithm;
use crate::{key::Key, sensitive, Metadata, Origin, Status};
use serde::{Deserialize, Serialize};

#[derive(Clone, Serialize, Deserialize, Debug, PartialEq, Eq)]
pub struct KeyInfo {
    pub id: u32,
    pub pub_id: String,
    pub status: Status,
    pub pub_key: sensitive::Bytes,
    pub origin: Origin,
    pub algorithm: Algorithm,
    pub metadata: Option<Metadata>,
}

impl From<&Key<super::Material>> for KeyInfo {
    fn from(key: &Key<super::Material>) -> Self {
        Self {
            id: key.id(),
            pub_id: key.pub_id().to_string(),
            algorithm: key.algorithm(),
            metadata: key.metadata().cloned(),
            origin: key.origin(),
            status: key.status(),
            pub_key: key.verifying_key().bytes(),
        }
    }
}
impl From<Key<super::Material>> for KeyInfo {
    fn from(mut key: Key<super::Material>) -> Self {
        Self {
            id: key.id(),
            pub_id: key.pub_id().to_string(),
            algorithm: key.algorithm(),
            metadata: key.take_metadata(),
            origin: key.origin(),
            status: key.status(),
            pub_key: key.verifying_key().bytes(),
        }
    }
}

impl From<KeyInfo> for u32 {
    fn from(key: KeyInfo) -> Self {
        key.id
    }
}
impl From<&KeyInfo> for u32 {
    fn from(key: &KeyInfo) -> Self {
        key.id
    }
}
impl From<KeyInfo> for String {
    fn from(key: KeyInfo) -> Self {
        key.pub_id.to_string()
    }
}
impl From<&KeyInfo> for String {
    fn from(key: &KeyInfo) -> Self {
        key.pub_id.to_string()
    }
}

pub type KeyringInfo = crate::KeyringInfo<KeyInfo>;
