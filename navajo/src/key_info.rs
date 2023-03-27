#[cfg(not(feature = "std"))]
use alloc::sync::Arc;
use serde::{Deserialize, Serialize};
use serde_json::Value;
#[cfg(feature = "std")]
use std::sync::Arc;

use crate::{Origin, Status};

#[derive(Debug, Clone, Serialize, Deserialize)]
/// Metadata for a particular key.
pub struct KeyInfo<A> {
    pub id: u32,
    pub status: Status,
    pub origin: Origin,
    pub algorithm: A,
    pub metadata: Option<Arc<Value>>,
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
#[cfg(feature = "aead")]
impl From<crate::aead::AeadKeyInfo> for KeyInfo<crate::aead::Algorithm> {
    fn from(info: crate::aead::AeadKeyInfo) -> Self {
        Self {
            id: info.id,
            algorithm: info.algorithm,
            origin: Origin::Navajo,
            status: info.status,
            metadata: info.metadata,
        }
    }
}
#[cfg(feature = "mac")]
impl From<crate::mac::MacKeyInfo> for KeyInfo<crate::mac::Algorithm> {
    fn from(info: crate::mac::MacKeyInfo) -> Self {
        Self {
            id: info.id,
            algorithm: info.algorithm,
            origin: info.origin,
            status: info.status,
            metadata: info.meta,
        }
    }
}
