use super::{verifying_key::VerifyingKey, Algorithm};
use crate::{sensitive, Origin, Status};
use alloc::sync::Arc;
use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Clone, Serialize, Deserialize)]
pub struct SignatureKeyInfo {
    pub id: u32,
    pub pub_id: String,
    pub status: Status,
    pub verifying_key: sensitive::Bytes,
    pub origin: Origin,
    pub algorithm: Algorithm,
    pub meta: Option<Arc<Value>>,
}
