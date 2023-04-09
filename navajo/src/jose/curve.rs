use core::str::FromStr;

use alloc::string::{String, ToString};
use serde::{Deserialize, Serialize};

use crate::{error::InvalidCurveError, strings::to_upper_remove_seperators};

/// [RFC 7518 #7.6](https://tools.ietf.org/html/rfc7518#section-7.6)
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, Hash)]
pub enum Curve {
    /// P-256 Elliptic Curve Digital Signature Algorithm (ECDSA)
    P256,

    /// P-384 Elliptic Curve Digital Signature Algorithm (ECDSA)
    P384,

    /// P-521 Elliptic Curve Digital Signature Algorithm (ECDSA)
    ///
    /// **Not supported**
    P521,

    /// Ed448 Edwards-curve Digital Signature Algorithm (EdDSA)
    ///
    /// **Not supported**
    Ed448,

    /// Ed25519 Edwards-curve Digital Signature Algorithm (EdDSA)
    Ed25519,

    /// X-25519 Elliptic Curve Diffie-Hellman (ECDH)
    ///
    /// **Not supported**
    X25519,

    /// X-448 Elliptic Curve Diffie-Hellman (ECDH)
    ///
    /// **Not supported**
    X448,
}

impl Curve {
    pub fn as_str(&self) -> &'static str {
        match self {
            Curve::P256 => "P-256",
            Curve::P384 => "P-384",
            Curve::P521 => "P-521",
            Curve::Ed25519 => "Ed25519",
            Curve::Ed448 => "Ed448",
            Curve::X25519 => "X25519",
            Curve::X448 => "X448",
        }
    }
}

impl TryFrom<String> for Curve {
    type Error = InvalidCurveError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Curve::from_str(value.as_str())
    }
}
impl TryFrom<&String> for Curve {
    type Error = InvalidCurveError;

    fn try_from(value: &String) -> Result<Self, Self::Error> {
        Curve::from_str(value)
    }
}
impl TryFrom<&str> for Curve {
    type Error = InvalidCurveError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        Curve::from_str(value)
    }
}
impl From<Curve> for String {
    fn from(value: Curve) -> Self {
        value.as_str().to_string()
    }
}
impl From<Curve> for &str {
    fn from(value: Curve) -> Self {
        value.as_str()
    }
}

impl FromStr for Curve {
    type Err = InvalidCurveError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match to_upper_remove_seperators(s).as_str() {
            "ED25519" => Ok(Curve::Ed25519),
            "ED448" => Ok(Curve::Ed448),
            "P256" => Ok(Curve::P256),
            "P384" => Ok(Curve::P384),
            "P521" => Ok(Curve::P521),
            "X25519" => Ok(Curve::X25519),
            "X448" => Ok(Curve::X448),
            _ => Err(InvalidCurveError(s.to_string())),
        }
    }
}
