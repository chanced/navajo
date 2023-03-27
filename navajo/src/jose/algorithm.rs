use core::str::FromStr;

use serde::{Deserialize, Serialize};
use strum::{Display, EnumIter, IntoStaticStr};

use crate::{error::InvalidAlgorithmError, sig, strings::to_upper_remove_seperators};

use super::{Curve, KeyType};

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, IntoStaticStr, Display, EnumIter,
)]
#[serde(try_from = "String", into = "&str")]
pub enum Algorithm {
    /// HMAC + SHA256
    ///
    #[strum(serialize = "HS256")]
    Hs256,
    /// HMAC + SHA384
    #[strum(serialize = "HS384")]
    Hs384,
    /// HMAC + SHA512
    #[strum(serialize = "HS512")]
    Hs512,
    /// ECDSA + SHA256
    #[strum(serialize = "ES256")]
    Es256,
    /// ECDSA + SHA384
    #[strum(serialize = "ES384")]
    Es384,
    #[strum(serialize = "RS256")]
    /// RSASSA-PKCS#1 v1.5 + SHA-256
    #[strum(serialize = "RS256")]
    Rs256,
    /// RSASSA-PKCS#1 v1.5 + SHA-384
    #[strum(serialize = "RS384")]
    Rs384,
    /// RSASSA-PKCS#1 v1.5 + SHA-512
    #[strum(serialize = "RS512")]
    Rs512,
    /// RSASSA-PSS + SHA-256
    #[strum(serialize = "PS256")]
    Ps256,
    /// RSASSA-PSS + SHA-384
    #[strum(serialize = "PS384")]
    Ps384,
    /// RSA-SSA-PSS + SHA-512
    #[strum(serialize = "PS512")]
    Ps512,
    /// Edwards-curve Digital Signature Algorithm (EdDSA)
    #[strum(serialize = "EdDSA")]
    EdDsa,
}

impl TryFrom<(KeyType, Curve)> for Algorithm {
    type Error = String;

    fn try_from((key_type, curve): (KeyType, Curve)) -> Result<Self, Self::Error> {
        match key_type {
            KeyType::Rsa => {
                Err("RSA algorithms can not be determined by the key type and curve".into())
            }
            KeyType::Oct => Err(
                "octet sequence algorithms can not be determined by the key type and curve".into(),
            ),
            KeyType::Ec => match curve {
                Curve::P256 => Ok(Algorithm::Es256),
                Curve::P384 => Ok(Algorithm::Es384),
                _ => Err("Unsupported curve for ECDSA".into()),
            },
            KeyType::Okp => match curve {
                Curve::Ed25519 => Ok(Algorithm::EdDsa),
                _ => Err("Unsupported curve for EdDSA".into()),
            },
        }
    }
}

impl From<crate::sig::Algorithm> for Algorithm {
    fn from(alg: crate::sig::Algorithm) -> Self {
        match alg {
            sig::Algorithm::Ed25519 => Algorithm::EdDsa,
            sig::Algorithm::Es256 => Algorithm::Es256,
            sig::Algorithm::Es384 => Algorithm::Es384,
        }
    }
}

impl FromStr for Algorithm {
    type Err = InvalidAlgorithmError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match to_upper_remove_seperators(s).as_str() {
            "HS256" => Ok(Algorithm::Hs256),
            "HS384" => Ok(Algorithm::Hs384),
            "HS512" => Ok(Algorithm::Hs512),
            "ES256" => Ok(Algorithm::Es256),
            "ES384" => Ok(Algorithm::Es384),
            "RS256" => Ok(Algorithm::Rs256),
            "RS384" => Ok(Algorithm::Rs384),
            "RS512" => Ok(Algorithm::Rs512),
            "PS256" => Ok(Algorithm::Ps256),
            "PS384" => Ok(Algorithm::Ps384),
            "PS512" => Ok(Algorithm::Ps512),
            "EDDSA" => Ok(Algorithm::EdDsa),
            _ => Err(s.into()),
        }
    }
}
impl TryFrom<String> for Algorithm {
    type Error = InvalidAlgorithmError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Algorithm::from_str(value.as_str())
    }
}
