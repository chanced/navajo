use serde::{Deserialize, Serialize};

use super::{Algorithm, Method, Segment};

/// Metadata for ciphertext.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CiphertextInfo {
    pub key_id: u32,
    pub algorithm: Algorithm,
    pub method: Method,
}
