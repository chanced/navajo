use alloc::sync::Arc;

use crate::{key::Key, Status};

use super::Algorithm;

pub struct AeadKeyInfo {
    pub id: u32,
    pub(crate) origin: crate::Origin,
    pub algorithm: Algorithm,
    pub status: Status,
    pub meta: Option<Arc<serde_json::Value>>,
}

impl AeadKeyInfo {
    pub(super) fn new(key: &Key<super::Material>) -> Self {
        Self {
            id: key.id(),
            algorithm: key.algorithm(),
            origin: key.origin(),
            status: key.status(),
            meta: key.meta(),
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
