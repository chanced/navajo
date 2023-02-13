use alloc::{sync::Arc, vec::Vec};
use serde::{Deserialize, Serialize};

use crate::{key::Key, Status};

use super::Algorithm;
#[derive(Debug, Clone, Serialize, Deserialize, Eq)]
pub struct MacKeyInfo {
    pub id: u32,
    pub origin: crate::Origin,
    pub algorithm: Algorithm,
    pub status: Status,
    pub meta: Option<Arc<serde_json::Value>>,
    /// The prefix provided during creation of an external key, if any.
    pub external_prefix: Option<Vec<u8>>,
    /// The header is prepended to all [`Tag`]s generated with this key unless
    /// [`Tag::omit_header`] was invoked.
    ///
    /// - For external keys, this will be the prefix if supplied.
    /// - For keys generated by navajo, this will be a version byte and the key ID.
    pub header: Vec<u8>,
}

impl PartialEq for MacKeyInfo {
    fn eq(&self, other: &Self) -> bool {
        self.id == other.id && self.algorithm == other.algorithm
    }
}

impl MacKeyInfo {
    pub(super) fn new(key: &Key<super::Material>) -> Self {
        Self {
            id: key.id(),
            algorithm: key.algorithm(),
            origin: key.origin(),
            status: key.status(),
            external_prefix: key.material().prefix().map(|p| p.to_vec()),
            header: key.header().to_vec(),
            meta: key.meta(),
        }
    }
}

impl From<MacKeyInfo> for u32 {
    fn from(value: MacKeyInfo) -> Self {
        value.id
    }
}
impl From<&MacKeyInfo> for u32 {
    fn from(value: &MacKeyInfo) -> Self {
        value.id
    }
}
impl From<&Key<super::Material>> for MacKeyInfo {
    fn from(key: &Key<super::Material>) -> Self {
        Self::new(key)
    }
}