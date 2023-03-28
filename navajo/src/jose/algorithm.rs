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
    /// HMAC using SHA-256
    #[strum(serialize = "HS256")]
    Hs256,

    /// HMAC using SHA-384
    #[strum(serialize = "HS384")]
    Hs384,

    /// HMAC using SHA-512
    #[strum(serialize = "HS512")]
    Hs512,

    /// ECDSA using P-256 curve and SHA-256
    #[strum(serialize = "ES256")]
    Es256,

    ///  ECDSA using secp256k1 curve and SHA-256
    #[strum(serialize = "ES256K")]
    Es256K,

    ///  ECDSA using P-384 curve and SHA-384
    #[strum(serialize = "ES384")]
    Es384,

    /// ECDSA using P-521 curve and SHA-512
    #[strum(serialize = "ES512")]
    Es512,

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

    /// Edwards-curve Digital Signature Algorithm (EdDSA) using Ed25519 or Ed448
    /// curves
    #[strum(serialize = "EdDSA")]
    EdDsa,

    /// RSAES using Optimal Asymmetric Encryption Padding (OAEP)
    #[strum(serialize = "RSA-OAEP")]
    RsaOaep,

    /// RSAES using OAEP with SHA-256 hash algorithm
    #[strum(serialize = "RSA-OAEP-256")]
    RsaOaep256,

    /// AES Key Wrap with a 128-bit key
    #[strum(serialize = "A128KW")]
    A128Kw,

    /// AES Key Wrap with a 192-bit key
    #[strum(serialize = "A192KW")]
    A192Kw,

    /// AES Key Wrap with a 256-bit key
    #[strum(serialize = "A256KW")]
    A256Kw,

    /// AES GCM using a 128-bit key
    #[strum(serialize = "A128GCM")]
    A128Gcm,

    /// AES GCM using a 192-bit key
    #[strum(serialize = "A192GCM")]
    A192Gcm,

    /// AES GCM using a 256-bit key
    #[strum(serialize = "A256GCM")]
    A256Gcm,

    /// AES CBC using a 128-bit key and HMAC-SHA-256 for authentication
    #[strum(serialize = "A128CBC-HS256")]
    A128CbcHs256,

    /// AES CBC using a 192-bit key and HMAC-SHA-384 for authentication
    #[strum(serialize = "A192CBC-HS384")]
    A192CbcHs384,

    /// AES CBC using a 256-bit key and HMAC-SHA-512 for authentication
    #[strum(serialize = "A256CBC-HS512")]
    A256CbcHs512,

    /// ChaCha20-Poly1305
    #[strum(serialize = "C20PKW")]
    C20Pkw,

    /// XChaCha20-Poly1305
    #[strum(serialize = "XC20PKW")]
    Xc20Pkw,
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
                _ => Err("unsupported curve".into()),
            },
            KeyType::Okp => match curve {
                Curve::Ed25519 => Ok(Algorithm::EdDsa),
                _ => Err("unsupported curve".into()),
            },
        }
    }
}

impl From<crate::dsa::Algorithm> for Algorithm {
    fn from(alg: crate::dsa::Algorithm) -> Self {
        match alg {
            dsa::Algorithm::Ed25519 => Algorithm::EdDsa,
            dsa::Algorithm::Es256 => Algorithm::Es256,
            dsa::Algorithm::Es384 => Algorithm::Es384,
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
            "ES256K" => Ok(Algorithm::Es256K),
            "ES384" => Ok(Algorithm::Es384),
            "ES512" => Ok(Algorithm::Es512),
            "RS256" => Ok(Algorithm::Rs256),
            "RS384" => Ok(Algorithm::Rs384),
            "RS512" => Ok(Algorithm::Rs512),
            "PS256" => Ok(Algorithm::Ps256),
            "PS384" => Ok(Algorithm::Ps384),
            "PS512" => Ok(Algorithm::Ps512),
            "EdDSA" => Ok(Algorithm::EdDsa),
            "RSAOAEP" => Ok(Algorithm::RsaOaep),
            "RSAOAEP256" => Ok(Algorithm::RsaOaep256),
            "A128KW" => Ok(Algorithm::A128Kw),
            "A192KW" => Ok(Algorithm::A192Kw),
            "A256KW" => Ok(Algorithm::A256Kw),
            "A128GCM" => Ok(Algorithm::A128Gcm),
            "A192GCM" => Ok(Algorithm::A192Gcm),
            "A256GCM" => Ok(Algorithm::A256Gcm),
            "A128CBCHS256" => Ok(Algorithm::A128CbcHs256),
            "A192CBCHS384" => Ok(Algorithm::A192CbcHs384),
            "A256CBCHS512" => Ok(Algorithm::A256CbcHs512),
            "C20PKW" => Ok(Algorithm::C20Pkw),
            "XC20PKW" => Ok(Algorithm::Xc20Pkw),

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
