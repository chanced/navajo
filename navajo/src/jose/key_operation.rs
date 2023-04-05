use core::{fmt::Display, str::FromStr};

use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(from = "String", into = "String")]
pub enum KeyOperation {
    Sign,
    Verify,
    Encrypt,
    Decrypt,
    WrapKey,
    UnwrapKey,
    DeriveKey,
    DeriveBits,
    Other(String),
}

impl KeyOperation {
    pub fn as_str(&self) -> &str {
        match self {
            KeyOperation::Sign => "sign",
            KeyOperation::Verify => "verify",
            KeyOperation::Encrypt => "encrypt",
            KeyOperation::Decrypt => "decrypt",
            KeyOperation::WrapKey => "wrapKey",
            KeyOperation::UnwrapKey => "unwrapKey",
            KeyOperation::DeriveKey => "deriveKey",
            KeyOperation::DeriveBits => "deriveBits",
            KeyOperation::Other(s) => s,
        }
    }

    pub fn into_json_value(self) -> Value {
        Value::String(self.as_str().to_string())
    }
}
impl Display for KeyOperation {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}
impl FromStr for KeyOperation {
    type Err = ();
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(KeyOperation::from(s))
    }
}
impl From<String> for KeyOperation {
    fn from(s: String) -> Self {
        KeyOperation::from_str(&s).unwrap()
    }
}
impl From<&String> for KeyOperation {
    fn from(s: &String) -> Self {
        KeyOperation::from(s.as_str())
    }
}

impl From<&str> for KeyOperation {
    fn from(s: &str) -> Self {
        match s.to_lowercase().as_str() {
            "sign" => KeyOperation::Sign,
            "verify" => KeyOperation::Verify,
            "encrypt" => KeyOperation::Encrypt,
            "decrypt" => KeyOperation::Decrypt,
            "wrapkey" => KeyOperation::WrapKey,
            "unwrapkey" => KeyOperation::UnwrapKey,
            "derivekey" => KeyOperation::DeriveKey,
            "derivebits" => KeyOperation::DeriveBits,
            _ => KeyOperation::Other(s.to_string()),
        }
    }
}

impl From<KeyOperation> for String {
    fn from(key_op: KeyOperation) -> Self {
        key_op.as_str().to_string()
    }
}

impl From<KeyOperation> for Value {
    fn from(key_op: KeyOperation) -> Self {
        key_op.into_json_value()
    }
}
