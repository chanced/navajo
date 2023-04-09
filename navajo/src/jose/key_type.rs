use alloc::string::ToString;
use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum KeyType {
    /// RSA
    Rsa,
    /// Elliptic Curve
    Ec,
    /// Octet Sequence (used to represent symmetric keys)
    Oct,
    /// Octet Key Pair
    Okp,
}

impl KeyType {
    pub fn as_str(&self) -> &'static str {
        match self {
            KeyType::Rsa => "RSA",
            KeyType::Ec => "EC",
            KeyType::Oct => "oct",
            KeyType::Okp => "OKP",
        }
    }
    pub fn into_json_value(self) -> Value {
        Value::String(self.as_str().to_string())
    }
}
impl From<KeyType> for Value {
    fn from(key_type: KeyType) -> Self {
        key_type.into_json_value()
    }
}
