use serde::{Deserialize, Serialize};
use serde_json::map::Keys;

use crate::jose::{KeyOperation, KeyType, KeyUse};
/// ```plaintext
/// "kid", "alg", "crv", "x", "y", "n", "e", "d", "p", "q", "dp", "dq", "qi", "x5u", "x5c", "x5t",
/// "x5t#S256"
/// ```
pub const RESERVED_METADATA_KEYS: [&str; 18] = [
    "kid", "d", "alg", "crv", "x", "y", "n", "e", "d", "p", "q", "dp", "dq", "qi", "x5u", "x5c",
    "x5t", "x5t#S256",
];
const KNOWN_METADATA_KEYS: [&str; 3] = ["use", "kty", "key_ops"];

#[derive(Serialize, Debug, Clone, PartialEq, Eq)]
pub struct Metadata {
    #[serde(rename = "kty", default)]
    key_type: Option<KeyType>,
    #[serde(rename = "use", default)]
    key_use: Option<KeyUse>,
    #[serde(rename = "key_ops", default)]
    key_operations: Option<Vec<KeyOperation>>,

    #[serde(flatten, default)]
    additional_fields: serde_json::Map<String, serde_json::Value>,

    #[serde(skip)]
    known_fields: serde_json::Map<String, serde_json::Value>,
}

impl Default for Metadata {
    fn default() -> Self {
        Self::new()
    }
}

impl<'de> Deserialize<'de> for Metadata {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct Data {
            #[serde(rename = "kty", default)]
            key_type: Option<KeyType>,
            #[serde(rename = "use", default)]
            key_use: Option<KeyUse>,
            #[serde(rename = "key_ops", default)]
            key_operations: Option<Vec<KeyOperation>>,
            #[serde(flatten, default)]
            additional_fields: serde_json::Map<String, serde_json::Value>,
        }

        let Data {
            key_type,
            key_use,
            key_operations,
            additional_fields,
        } = Data::deserialize(deserializer)?;

        for key in additional_fields.keys() {
            if RESERVED_METADATA_KEYS.contains(&key.as_str()) {
                return Err(serde::de::Error::custom(format!(
                    "Key '{}' is reserved and cannot be used as a custom metadata key",
                    key
                )));
            }
        }
        let mut known_fields: serde_json::Map<String, serde_json::Value> = serde_json::Map::new();
        if let Some(key_use) = key_use.as_ref() {
            known_fields.insert(
                "use".to_string(),
                serde_json::Value::String(key_use.to_string()),
            );
        }
        if let Some(key_type) = key_type.as_ref() {
            known_fields.insert("kty".to_string(), key_type.as_str().into());
        }
        if let Some(key_operations) = key_operations.as_ref() {
            known_fields.insert(
                "key_ops".to_string(),
                serde_json::Value::Array(
                    key_operations
                        .iter()
                        .map(|k| serde_json::Value::String(k.to_string()))
                        .collect(),
                ),
            );
        }
        Ok(Metadata {
            key_type,
            key_use,
            key_operations,
            additional_fields,
            known_fields,
        })
    }
}

impl Metadata {
    pub fn new() -> Self {
        Self {
            key_type: None,
            key_use: None,
            key_operations: None,
            additional_fields: serde_json::Map::new(),
            known_fields: serde_json::Map::new(),
        }
    }

    pub fn key_type(&self) -> Option<&KeyType> {
        self.key_type.as_ref()
    }

    pub fn key_use(&self) -> Option<&KeyUse> {
        self.key_use.as_ref()
    }

    pub fn key_operations(&self) -> Option<&Vec<KeyOperation>> {
        self.key_operations.as_ref()
    }

    pub fn additional_fields(&self) -> &serde_json::Map<String, serde_json::Value> {
        &self.additional_fields
    }

    pub fn additional_fields_mut(&mut self) -> &mut serde_json::Map<String, serde_json::Value> {
        &mut self.additional_fields
    }

    pub fn set_key_type(&mut self, key_type: Option<KeyType>) {
        if let Some(key_type) = key_type.as_ref() {
            self.known_fields
                .insert("kty".to_string(), key_type.as_str().into());
        } else {
            self.known_fields.remove("kty");
        }
        self.key_type = key_type;
    }

    pub fn set_key_use(&mut self, key_use: Option<KeyUse>) {
        if let Some(key_use) = key_use.as_ref() {
            self.known_fields.insert(
                "use".to_string(),
                serde_json::Value::String(key_use.to_string()),
            );
        } else {
            self.known_fields.remove("use");
        }

        self.key_use = key_use;
    }

    pub fn set_key_operations(&mut self, key_operations: Option<Vec<KeyOperation>>) {
        if let Some(key_ops) = key_operations.as_ref() {
            self.known_fields.insert(
                "key_ops".to_string(),
                serde_json::Value::Array(
                    key_ops
                        .iter()
                        .map(|k| serde_json::Value::String(k.to_string()))
                        .collect(),
                ),
            );
        } else {
            self.known_fields.remove("key_ops");
        }
        self.key_operations = key_operations;
    }

    pub fn get(&self, key: &str) -> Option<&serde_json::Value> {
        match key {
            "kty" | "use" | "key_ops" => self.known_fields.get(key),
            _ => self.additional_fields.get(key),
        }
    }

    fn known_keys(&self) -> Vec<&'static str> {
        let mut known_keys = Vec::new();
        if self.key_type.is_some() {
            known_keys.push("kty");
        }
        if self.key_use.is_some() {
            known_keys.push("use");
        }
        if self.key_operations.is_some() {
            known_keys.push("key_ops");
        }
        known_keys
    }

    pub fn keys(&self) -> MetadataKeys {
        MetadataKeys {
            known_keys: self.known_keys(),
            known_keys_iter: KNOWN_METADATA_KEYS.iter(),
            additional_keys: self.additional_fields.keys(),
        }
    }
}

pub struct MetadataKeys<'a> {
    known_keys: Vec<&'static str>,
    known_keys_iter: core::slice::Iter<'a, &'static str>,
    additional_keys: Keys<'a>,
}
