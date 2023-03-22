use core::{fmt::Display, str::FromStr};

use alloc::borrow::Cow;
use alloc::vec::Vec;
use serde::{Deserialize, Serialize, Serializer};

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum KeyUse {
    Signature,
    Encryption,
    Other(String),
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
impl KeyUse {
    fn as_str(&self) -> &str {
        match self {
            KeyUse::Signature => "sig",
            KeyUse::Encryption => "enc",
            KeyUse::Other(s) => s,
        }
    }
}
impl Serialize for KeyUse {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(self.to_string().as_str())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
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
impl Display for KeyOperation {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            KeyOperation::Sign => write!(f, "sign"),
            KeyOperation::Verify => write!(f, "verify"),
            KeyOperation::Encrypt => write!(f, "encrypt"),
            KeyOperation::Decrypt => write!(f, "decrypt"),
            KeyOperation::WrapKey => write!(f, "wrapKey"),
            KeyOperation::UnwrapKey => write!(f, "unwrapKey"),
            KeyOperation::DeriveKey => write!(f, "deriveKey"),
            KeyOperation::DeriveBits => write!(f, "deriveBits"),
            KeyOperation::Other(s) => write!(f, "{s}"),
        }
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
impl Serialize for KeyOperation {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.to_string())
    }
}
impl<'de> Deserialize<'de> for KeyOperation {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        Ok(KeyOperation::from(s))
    }
}

#[derive(Default, Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Jwk {
    #[serde(rename = "kid", skip_serializing_if = "Option::is_none")]
    pub key_id: Option<String>,

    #[serde(rename = "alg")]
    pub algorithm: Cow<'static, str>,

    #[serde(rename = "kty")]
    pub key_type: Cow<'static, str>,

    #[serde(rename = "use", skip_serializing_if = "Option::is_none")]
    pub key_use: Option<Cow<'static, str>>,

    #[serde(rename = "key_ops", skip_serializing_if = "Vec::is_empty")]
    pub key_operations: Vec<KeyOperation>,

    #[serde(rename = "crv", skip_serializing_if = "Option::is_none")]
    pub curve: Option<Cow<'static, str>>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub x: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub y: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub n: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub e: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub d: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub p: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub q: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub dp: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub dq: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub qi: Option<String>,
}

pub type Jwks = Vec<Jwk>;
