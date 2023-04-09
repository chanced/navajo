use serde::{Deserialize, Serialize};

use super::{Algorithm, Method};

/// Metadata for ciphertext.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CiphertextInfo {
    pub key_id: u32,
    #[serde(rename = "alg")]
    pub algorithm: Algorithm,
    pub method: Method,
}
