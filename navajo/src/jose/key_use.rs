use core::{fmt::Display, str::FromStr};

use alloc::string::String;
use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(from = "String", into = "String")]
pub enum KeyUse {
    Signature,
    Encryption,
    Other(String),
}

impl KeyUse {
    pub fn as_str(&self) -> &str {
        match self {
            KeyUse::Signature => "sig",
            KeyUse::Encryption => "enc",
            KeyUse::Other(s) => s,
        }
    }
    pub fn into_json_value(self) -> Value {
        Value::String(self.as_str().to_string())
    }
}

impl Display for KeyUse {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

impl FromStr for KeyUse {
    type Err = ();
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(KeyUse::from(s))
    }
}

impl From<String> for KeyUse {
    fn from(s: String) -> Self {
        KeyUse::from(s.as_str())
    }
}
impl From<KeyUse> for String {
    fn from(ku: KeyUse) -> Self {
        ku.as_str().to_string()
    }
}
impl From<&String> for KeyUse {
    fn from(s: &String) -> Self {
        KeyUse::from(s.as_str())
    }
}
impl From<&str> for KeyUse {
    fn from(s: &str) -> Self {
        match s.to_lowercase().as_str() {
            "sig" => KeyUse::Signature,
            "enc" => KeyUse::Encryption,
            _ => KeyUse::Other(s.to_string()),
        }
    }
}

impl From<KeyUse> for Value {
    fn from(key_use: KeyUse) -> Self {
        key_use.into_json_value()
    }
}

impl From<&KeyUse> for Value {
    fn from(key_use: &KeyUse) -> Self {
        key_use.clone().into_json_value()
    }
}
