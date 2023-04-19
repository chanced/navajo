use core::str::FromStr;

use alloc::{format, string::String};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]

pub enum Kind {
    #[serde(rename = "AEAD")]
    Aead,
    #[serde(rename = "DAEAD")]
    Daead,
    // #[serde(rename="HPKE")] // TODO: Enable this once HPKE is implemented
    // Hpke,
    #[serde(rename = "MAC")]
    Mac,
    #[serde(rename = "DSA")]
    Dsa,
}

impl Kind {
    pub fn as_str(&self) -> &'static str {
        match self {
            Kind::Aead => "AEAD",
            Kind::Daead => "DAEAD",
            // PrimitiveType::Hpke => "HPKE",
            Kind::Mac => "MAC",
            Kind::Dsa => "Signature",
        }
    }
    pub fn as_u8(&self) -> u8 {
        match self {
            Kind::Aead => 0,
            Kind::Daead => 1,
            // PrimitiveType::Hpke => 2,
            Kind::Mac => 3,
            Kind::Dsa => 4,
        }
    }
    /// Returns true if the primitive Kind is DSA (i.e. a signature algorithm)
    pub fn is_signature(&self) -> bool {
        matches!(self, Kind::Dsa)
    }
    /// Returns `true` if the primitive Kind is `Dsa` (i.e. a signature algorithm)
    pub fn is_dsa(&self) -> bool {
        matches!(self, Kind::Dsa)
    }
    /// Returns `true` if the primitive is `Aead `
    pub fn is_aead(&self) -> bool {
        matches!(self, Kind::Aead)
    }
    /// Returns `true` if the primitive is `Daead`
    pub fn is_daead(&self) -> bool {
        matches!(self, Kind::Daead)
    }
    /// Returns `true` if the primitive is `Mac`
    pub fn is_mac(&self) -> bool {
        matches!(self, Kind::Mac)
    }
}

impl FromStr for Kind {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_uppercase().as_str() {
            "AEAD" => Ok(Kind::Aead),
            "DAEAD" => Ok(Kind::Daead),
            // "HPKE" => Ok(PrimitiveType::Hpke),
            "MAC" => Ok(Kind::Mac),
            "SIGNATURE" => Ok(Kind::Dsa),
            _ => Err(format!("invalid primitive type: \"{s}\"")),
        }
    }
}
impl core::fmt::Display for Kind {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}
impl From<Kind> for u8 {
    fn from(pt: Kind) -> Self {
        pt.as_u8()
    }
}
impl TryFrom<u8> for Kind {
    type Error = String;
    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Kind::Aead),
            1 => Ok(Kind::Daead),
            // 2 => Ok(PrimitiveType::Hpke),
            3 => Ok(Kind::Mac),
            4 => Ok(Kind::Dsa),
            _ => Err(format!("invalid primitive type: \"{value}\"")),
        }
    }
}
