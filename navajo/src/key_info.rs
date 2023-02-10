use alloc::sync::Arc;

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::{key::KeyMaterial, mac::MacKeyInfo, Origin, Status};

#[derive(Debug, Clone, Serialize, Deserialize)]
/// Metadata for a particular key.
pub struct KeyInfo<A> {
    pub id: u32,
    pub status: Status,
    pub origin: Origin,
    pub algorithm: A,
    pub meta: Option<Arc<Value>>,
}
impl<A> PartialEq for KeyInfo<A>
where
    A: PartialEq,
{
    fn eq(&self, other: &Self) -> bool {
        self.id == other.id && self.algorithm == other.algorithm
    }
}
impl<A> Eq for KeyInfo<A> where A: Eq {}
impl<A> From<KeyInfo<A>> for u32 {
    fn from(ki: KeyInfo<A>) -> Self {
        ki.id
    }
}
impl<A> From<&KeyInfo<A>> for u32 {
    fn from(ki: &KeyInfo<A>) -> Self {
        ki.id
    }
}
impl From<MacKeyInfo> for KeyInfo<crate::mac::Algorithm> {
    fn from(info: MacKeyInfo) -> Self {
        Self {
            id: info.id,
            algorithm: info.algorithm,
            origin: info.origin,
            status: info.status,
            meta: info.meta.map(Arc::new),
        }
    }
}