use super::Algorithm;
use crate::{key::Key, sensitive, Metadata, Origin, Status};
use alloc::sync::Arc;
use serde::{Deserialize, Serialize};

#[derive(Clone, Serialize, Deserialize)]
pub struct DsaKeyInfo {
    pub id: u32,
    pub pub_id: String,
    pub status: Status,
    pub verifying_key: sensitive::Bytes,
    pub origin: Origin,
    pub algorithm: Algorithm,
    pub metadata: Option<Arc<Metadata>>,
}
impl DsaKeyInfo {
    pub(crate) fn new(key: &Key<super::signing_key::SigningKey>) -> Self {
        Self {
            id: key.id(),
            pub_id: key.pub_id().to_string(),
            algorithm: key.algorithm(),
            metadata: key.metadata(),
            origin: key.origin(),
            status: key.status(),
            verifying_key: key.verifying_key().bytes(),
        }
    }
}
