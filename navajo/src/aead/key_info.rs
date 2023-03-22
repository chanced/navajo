use alloc::sync::Arc;
use serde::Serialize;

use crate::{key::Key, Status};

use super::Algorithm;

#[derive(Serialize, Clone, Debug)]
pub struct AeadKeyInfo {
    pub id: u32,
    pub algorithm: Algorithm,
    pub status: Status,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata: Option<Arc<serde_json::Value>>,
}

impl AeadKeyInfo {
    pub(super) fn new(key: &Key<super::Material>) -> Self {
        Self {
            id: key.id(),
            algorithm: key.algorithm(),
            status: key.status(),
            metadata: key.meta(),
        }
    }
}

impl From<AeadKeyInfo> for u32 {
    fn from(value: AeadKeyInfo) -> Self {
        value.id
    }
}
impl From<&AeadKeyInfo> for u32 {
    fn from(value: &AeadKeyInfo) -> Self {
        value.id
    }
}
impl From<&Key<super::Material>> for AeadKeyInfo {
    fn from(key: &Key<super::Material>) -> Self {
        Self::new(key)
    }
}
impl From<Key<super::Material>> for AeadKeyInfo {
    fn from(key: Key<super::Material>) -> Self {
        Self::new(&key)
    }
}
