use core::str::FromStr;

use serde::{Deserialize, Serialize};

use crate::strings::to_upper_remove_seperators;

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum Zip {
    Deflate,
    Other(String),
}
impl Zip {
    pub fn as_str(&self) -> &str {
        match self {
            Zip::Deflate => "DEF",
            Zip::Other(s) => s,
        }
    }
}

impl From<&str> for Zip {
    fn from(s: &str) -> Self {
        match to_upper_remove_seperators(s).as_str() {
            "DEF" => Self::Deflate,
            _ => Self::Other(s.to_string()),
        }
    }
}
impl From<String> for Zip {
    fn from(s: String) -> Self {
        Self::from(s.as_str())
    }
}
impl From<&String> for Zip {
    fn from(s: &String) -> Self {
        Self::from(s.as_str())
    }
}
impl FromStr for Zip {
    type Err = ();
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(Self::from(s))
    }
}

impl From<Zip> for String {
    fn from(value: Zip) -> Self {
        value.as_str().to_string()
    }
}

impl Serialize for Zip {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}
impl<'de> Deserialize<'de> for Zip {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        Ok(Self::from(s))
    }
}
