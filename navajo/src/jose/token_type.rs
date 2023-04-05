use core::fmt::Display;

use alloc::string::String;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(from = "String", into = "String")]
pub enum TokenType {
    Jwt,
    Other(String),
}
impl TokenType {
    pub fn new(s: &str) -> Self {
        Self::from(s)
    }
    pub fn is_jwt(&self) -> bool {
        matches!(self, TokenType::Jwt)
    }
    pub fn is_other(&self) -> bool {
        matches!(self, TokenType::Other(_))
    }
    pub fn as_str(&self) -> &str {
        match self {
            TokenType::Jwt => "JWT",
            TokenType::Other(s) => s.as_str(),
        }
    }
}
impl Display for TokenType {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            TokenType::Jwt => write!(f, "JWT"),
            TokenType::Other(s) => write!(f, "{s}"),
        }
    }
}
impl From<String> for TokenType {
    fn from(s: String) -> Self {
        Self::from(s.as_str())
    }
}

impl From<&str> for TokenType {
    fn from(s: &str) -> Self {
        match s.to_uppercase().as_str() {
            "JWT" => TokenType::Jwt,
            _ => TokenType::Other(s.to_string()),
        }
    }
}

impl From<&String> for TokenType {
    fn from(value: &String) -> Self {
        Self::from(value.as_str())
    }
}

impl From<TokenType> for String {
    fn from(t: TokenType) -> Self {
        Self::from(&t)
    }
}

impl From<&TokenType> for String {
    fn from(t: &TokenType) -> Self {
        match t {
            TokenType::Jwt => "JWT".to_string(),
            TokenType::Other(s) => s.clone(),
        }
    }
}

impl<'a> From<&'a TokenType> for &'a str {
    fn from(t: &'a TokenType) -> Self {
        match t {
            TokenType::Jwt => "JWT",
            TokenType::Other(s) => s.as_str(),
        }
    }
}
