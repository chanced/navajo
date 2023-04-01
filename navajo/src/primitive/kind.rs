use core::str::FromStr;

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
    #[serde(rename = "Signature")]
    Signature,
}

impl Kind {
    pub fn as_str(&self) -> &'static str {
        match self {
            Kind::Aead => "AEAD",
            Kind::Daead => "DAEAD",
            // PrimitiveType::Hpke => "HPKE",
            Kind::Mac => "MAC",
            Kind::Signature => "Signature",
        }
    }
    pub fn as_u8(&self) -> u8 {
        match self {
            Kind::Aead => 0,
            Kind::Daead => 1,
            // PrimitiveType::Hpke => 2,
            Kind::Mac => 3,
            Kind::Signature => 4,
        }
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
            "SIGNATURE" => Ok(Kind::Signature),
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
            4 => Ok(Kind::Signature),
            _ => Err(format!("invalid primitive type: \"{value}\"")),
        }
    }
}
