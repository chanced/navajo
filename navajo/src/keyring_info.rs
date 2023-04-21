use serde::{Deserialize, Serialize};

use crate::Kind;

#[derive(Clone, Serialize, Deserialize, Debug, PartialEq, Eq)]
pub struct KeyringInfo<T> {
    #[serde(rename = "v")]
    pub version: u8,
    pub keys: Vec<T>,
    pub kind: Kind,
}
