use core::str::FromStr;

use super::{Algorithm, Jwk, Zip};
use crate::{b64, error::DecodeError};
use base64::engine::{general_purpose::URL_SAFE_NO_PAD, Engine};
use serde::{Deserialize, Serialize};
use url::Url;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Header {
    /// Specifies the cryptographic algorithm used to secure the JWT.
    #[serde(rename = "alg")]
    pub algorithm: Algorithm,

    /// The `"kid"` field is used to identify the key used to sign the JWT.
    #[serde(rename = "kid", skip_serializing_if = "Option::is_none")]
    pub key_id: Option<String>,

    /// The `"cty"` field is used to indicate the MIME type of the token's payload.
    /// This field is optional, but if present, its value should be a string that
    /// identifies the type of data in the token's payload.
    ///
    /// The value of the "cty" field can be any valid MIME media type. For example,
    /// it could be set to "application/json" to indicate that the payload is a JSON
    /// object, or "text/plain" to indicate that the payload is plain text.
    #[serde(rename = "cty", skip_serializing_if = "Option::is_none")]
    pub content_type: Option<String>,

    /// The `"typ"` is used to indicate the type of the token.
    ///
    /// The value of the "typ" field is typically set to "JWT" to indicate that
    /// the token is a JSON Web Token.
    #[serde(rename = "typ", skip_serializing_if = "Option::is_none")]
    pub token_type: Option<String>,

    /// the `"jku"`field is used to specify the URL where the JWK set can be
    /// found.
    #[serde(rename = "jku", skip_serializing_if = "Option::is_none")]
    pub jwks_url: Option<Url>,

    /// The `"jwk"` field can be used to provide the JWK used to sign the JWT.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub jwk: Option<Jwk>,

    /// the `"x5u"` field is used to specify the URL where the X.509 certificate
    /// chain can be found.
    #[serde(rename = "x5u", skip_serializing_if = "Option::is_none")]
    pub x509_url: Option<url::Url>,

    /// the `"x5c"` field is used to provide the X.509 certificate chain.
    #[serde(
        rename = "x5c",
        with = "b64::optional_seq_url_safe",
        skip_serializing_if = "Option::is_none",
        default
    )]
    pub x509_cert_chain: Option<Vec<Vec<u8>>>,

    /// The value of the `"x5t"` field is a base64_url encoded string that represents
    /// the SHA-1 thumbprint of the X.509 certificate. The SHA-1 thumbprint is
    /// calculated by taking the SHA-1 hash of the DER-encoded X.509 certificate
    /// and then base64-encoding the result.
    #[serde(
        rename = "x5t",
        with = "b64::optional_url_safe",
        skip_serializing_if = "Option::is_none",
        default
    )]
    pub x509_cert_sha1_thumbprint: Option<Vec<u8>>,

    /// The "x5t#S256" field in a JWT (JSON Web Token) header is used to include
    /// the SHA-256 thumbprint of the X.509 certificate that was used to sign
    /// the JWT.
    ///
    /// The value of the "x5t#S256" field is a base64-encoded string that
    /// represents the SHA-256 thumbprint of the X.509 certificate. The SHA-256
    /// thumbprint is calculated by taking the SHA-256 hash of the DER-encoded
    /// X.509 certificate and then base64-encoding the result.
    #[serde(
        rename = "x5t#S256",
        with = "b64::optional_url_safe",
        skip_serializing_if = "Option::is_none",
        default
    )]
    pub x509_cert_sha256_thumbprint: Option<Vec<u8>>,

    /// The `"crit"` field is used to indicate that extensions to this
    /// specification and/or [JWS] are being used that MUST be understood and
    /// processed.  If the "crit" field is not understood, then the JWT must
    /// be rejected.
    #[serde(rename = "crit", skip_serializing_if = "Vec::is_empty", default)]
    pub critical: Vec<String>,

    #[serde(rename = "enc", skip_serializing_if = "Option::is_none")]
    pub encryption: Option<String>, // TODO: the possible values need to be added to the Encryption enum

    #[serde(rename = "zip", skip_serializing_if = "Option::is_none")]
    pub zip: Option<Zip>,

    #[serde(rename = "iv", skip_serializing_if = "Option::is_none")]
    pub iv: Option<Vec<u8>>,

    #[serde(flatten)]
    pub additional_fields: serde_json::Map<String, serde_json::Value>,
}

impl TryFrom<&str> for Header {
    type Error = DecodeError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        Self::try_from(value.as_bytes())
    }
}
impl FromStr for Header {
    type Err = DecodeError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::try_from(s)
    }
}
impl TryFrom<&[u8]> for Header {
    type Error = DecodeError;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        let decoded = URL_SAFE_NO_PAD.decode(value)?;
        Ok(serde_json::from_slice(&decoded)?)
    }
}
impl TryFrom<String> for Header {
    type Error = DecodeError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::try_from(value.as_bytes())
    }
}

impl TryFrom<&String> for Header {
    type Error = DecodeError;

    fn try_from(value: &String) -> Result<Self, Self::Error> {
        Self::try_from(value.as_bytes())
    }
}
