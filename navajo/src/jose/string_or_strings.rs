use core::fmt::Display;

use alloc::{
    string::{String, ToString},
    vec,
    vec::Vec,
};
use serde::{de::Visitor, Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StringOrStrings {
    String(String),
    Strings(Vec<String>),
}
impl Display for StringOrStrings {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        match self {
            Self::String(s) => write!(f, "{s}"),
            Self::Strings(v) => write!(f, "{}", v.join(", ")),
        }
    }
}
impl StringOrStrings {
    pub fn push(&mut self, value: String) {
        match self {
            Self::String(s) => {
                let v = vec![s.clone(), value];
                *self = Self::Strings(v);
            }
            Self::Strings(v) => v.push(value),
        }
    }
    pub fn as_vec(&self) -> Vec<&str> {
        match self {
            Self::String(s) => vec![s],
            Self::Strings(v) => v.iter().map(|s| s.as_str()).collect(),
        }
    }
    pub fn contains(&self, value: &str) -> bool {
        match self {
            Self::String(s) => s == value,
            Self::Strings(v) => v.contains(&value.to_string()),
        }
    }
}
impl Extend<String> for StringOrStrings {
    fn extend<T: IntoIterator<Item = String>>(&mut self, iter: T) {
        match self {
            Self::String(s) => {
                let mut v = Vec::with_capacity(2);
                v.push(s.clone());
                v.extend(iter);
                *self = Self::Strings(v);
            }
            Self::Strings(v) => v.extend(iter),
        }
    }
}

impl Serialize for StringOrStrings {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        match self {
            Self::String(s) => serializer.serialize_str(s),
            Self::Strings(v) => serializer.collect_seq(v),
        }
    }
}

impl<'de> Deserialize<'de> for StringOrStrings {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct StringOrStringsVisitor;

        impl<'de> Visitor<'de> for StringOrStringsVisitor {
            type Value = StringOrStrings;

            fn expecting(&self, formatter: &mut alloc::fmt::Formatter) -> alloc::fmt::Result {
                formatter.write_str("a string or an array of strings")
            }
            fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                Ok(StringOrStrings::String(v.to_string()))
            }
            fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
            where
                A: serde::de::SeqAccess<'de>,
            {
                let mut strings = Vec::new();
                while let Some(s) = seq.next_element()? {
                    strings.push(s);
                }
                Ok(StringOrStrings::Strings(strings))
            }
        }

        deserializer.deserialize_any(StringOrStringsVisitor)
    }
}

impl From<String> for StringOrStrings {
    fn from(s: String) -> Self {
        Self::String(s)
    }
}
impl From<Vec<String>> for StringOrStrings {
    fn from(v: Vec<String>) -> Self {
        Self::Strings(v)
    }
}

impl From<&str> for StringOrStrings {
    fn from(s: &str) -> Self {
        Self::String(s.to_string())
    }
}
impl From<&String> for StringOrStrings {
    fn from(s: &String) -> Self {
        Self::String(s.to_string())
    }
}
impl From<&[String]> for StringOrStrings {
    fn from(v: &[String]) -> Self {
        Self::Strings(v.to_vec())
    }
}
impl From<&[&str]> for StringOrStrings {
    fn from(v: &[&str]) -> Self {
        Self::Strings(v.iter().map(|s| s.to_string()).collect())
    }
}

impl From<Vec<&str>> for StringOrStrings {
    fn from(v: Vec<&str>) -> Self {
        Self::from(&v[..])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_serde() {
        #[derive(Serialize, Debug)]
        struct Input {
            string: String,
            strings: Vec<String>,
        }

        #[derive(Serialize, Deserialize, PartialEq, Eq, Debug)]
        struct Expected {
            string: StringOrStrings,
            strings: StringOrStrings,
        }
        let strings = vec!["string_1".to_string(), "string_2".to_string()];
        let string = "string val".to_string();
        let input = Input {
            string: string.clone(),
            strings: strings.clone(),
        };

        let input_json = serde_json::to_string(&input).unwrap();

        let expected = Expected {
            string: string.into(),
            strings: strings.into(),
        };
        let result = serde_json::from_str::<Expected>(&input_json).unwrap();

        assert_eq!(expected, result);
    }
}
