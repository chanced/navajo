use alloc::{format, string::String, vec::Vec};
use serde::{Deserialize, Serialize};

use crate::jose::{KeyOperation, KeyUse};
/// ```plaintext
/// "kid", "kty", "alg", "crv", "x", "y", "n", "e", "d", "p", "q", "dp", "dq", "qi", "x5u", "x5c", "x5t",
/// "x5t#S256"
/// ```
pub const RESERVED_METADATA_KEYS: [&str; 19] = [
    "kid", "kty", "d", "alg", "crv", "x", "y", "n", "e", "d", "p", "q", "dp", "dq", "qi", "x5u",
    "x5c", "x5t", "x5t#S256",
];

#[derive(Serialize, Debug, Clone, PartialEq, Eq)]
pub struct Metadata {
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
            #[serde(rename = "use", default)]
            key_use: Option<KeyUse>,
            #[serde(rename = "key_ops", default)]
            key_operations: Option<Vec<KeyOperation>>,
            #[serde(flatten, default)]
            additional_fields: serde_json::Map<String, serde_json::Value>,
        }

        let Data {
            key_use,
            key_operations,
            additional_fields,
        } = Data::deserialize(deserializer)?;

        for key in additional_fields.keys() {
            if RESERVED_METADATA_KEYS.contains(&key.as_str()) {
                return Err(serde::de::Error::custom(format!(
                    "key '{key}' is reserved and cannot be used as a custom metadata key",
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
            key_use: None,
            key_operations: None,
            additional_fields: serde_json::Map::new(),
            known_fields: serde_json::Map::new(),
        }
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

    pub fn insert(
        &mut self,
        key: String,
        value: serde_json::Value,
    ) -> Result<Option<serde_json::Value>, serde_json::Error> {
        match key.as_str() {
            "use" => {
                let key_use: KeyUse = serde_json::from_value(value)?;
                let old = self
                    .set_key_use(Some(key_use))
                    .map(|old| old.into_json_value());

                Ok(old)
            }
            "key_ops" => {
                let key_ops: Option<Vec<KeyOperation>> = serde_json::from_value(value)?;
                let old = self
                    .set_key_operations(key_ops)
                    .map(|old| old.into_iter().map(|op| op.into_json_value()).collect());

                Ok(old)
            }
            _ => Ok(self.additional_fields.insert(key, value)),
        }
    }

    pub fn set_key_use(&mut self, key_use: Option<KeyUse>) -> Option<KeyUse> {
        if let Some(key_use) = key_use.as_ref() {
            self.known_fields.insert(
                "use".to_string(),
                serde_json::Value::String(key_use.to_string()),
            );
        } else {
            self.known_fields.remove("use");
        }
        let old = self.key_use.take();
        self.key_use = key_use;
        old
    }

    pub fn set_key_operations(
        &mut self,
        key_operations: Option<Vec<KeyOperation>>,
    ) -> Option<Vec<KeyOperation>> {
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
        let old = self.key_operations.take();
        self.key_operations = key_operations;
        old
    }

    pub fn get(&self, key: &str) -> Option<&serde_json::Value> {
        match key {
            "kty" | "use" | "key_ops" => self.known_fields.get(key),
            _ => self.additional_fields.get(key),
        }
    }

    pub fn keys(&self) -> Keys {
        Keys {
            known: self.known_fields.keys(),
            additional: self.additional_fields.keys(),
        }
    }
}

pub struct Iter<'a> {
    known: serde_json::map::Iter<'a>,
    additional: serde_json::map::Iter<'a>,
}
impl<'a> Iterator for Iter<'a> {
    type Item = (&'a String, &'a serde_json::Value);
    fn next(&mut self) -> Option<Self::Item> {
        self.known.next().or_else(|| self.additional.next())
    }
}

pub struct Values<'a> {
    known: serde_json::map::Values<'a>,
    additional: serde_json::map::Values<'a>,
}

impl<'a> Iterator for Values<'a> {
    type Item = &'a serde_json::Value;

    fn next(&mut self) -> Option<Self::Item> {
        self.known.next().or_else(|| self.additional.next())
    }
}

pub struct Keys<'a> {
    known: serde_json::map::Keys<'a>,
    additional: serde_json::map::Keys<'a>,
}
impl<'a> Iterator for Keys<'a> {
    type Item = &'a String;
    fn next(&mut self) -> Option<Self::Item> {
        self.known.next().or_else(|| self.additional.next())
    }
}

#[cfg(test)]
mod tests {
    use alloc::vec;

    use super::*;
    #[test]
    fn test_keys_iter() {
        let mut meta = Metadata::new();
        meta.set_key_operations(vec![KeyOperation::Sign, KeyOperation::Verify].into());
    }
}
