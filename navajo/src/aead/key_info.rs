use serde::{Deserialize, Serialize};

use crate::{Key, Metadata, Origin, Status};

#[derive(Clone, Serialize, Deserialize, Debug, PartialEq, Eq)]
pub struct KeyInfo {
    pub id: u32,
    pub status: Status,
    pub origin: Origin,
    pub algorithm: super::Algorithm,
    pub metadata: Option<Metadata>,
}
impl From<Key<super::Material>> for KeyInfo {
    fn from(mut value: Key<super::Material>) -> Self {
        Self {
            id: value.id(),
            algorithm: value.algorithm(),
            metadata: value.take_metadata(),
            origin: value.origin(),
            status: value.status(),
        }
    }
}
impl From<&Key<super::Material>> for KeyInfo {
    fn from(value: &Key<super::Material>) -> Self {
        Self {
            id: value.id(),
            algorithm: value.algorithm(),
            metadata: value.metadata().cloned(),
            origin: value.origin(),
            status: value.status(),
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
pub type KeyringInfo = crate::KeyringInfo<KeyInfo>;
