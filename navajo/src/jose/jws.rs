use core::ops::Deref;

use crate::{dsa::Signature, error::DecodeError};
use base64::engine::{general_purpose::URL_SAFE_NO_PAD, Engine};
use serde::Serialize;

use super::{Claims, Header};

pub fn decode_jws<P>(jws: &str) -> Result<(Header, Vec<u8>, Vec<u8>), DecodeError> {
    let split: Vec<&str> = jws.split('.').collect();

    if split.len() != 3 {
        return Err("malformed jws".into());
    }
    let header: Vec<u8> = URL_SAFE_NO_PAD.decode(split[0])?;
    let payload: Vec<u8> = URL_SAFE_NO_PAD.decode(split[1])?;
    let signature: Vec<u8> = URL_SAFE_NO_PAD.decode(split[2])?;
    let header: Header = serde_json::from_slice(&header)?;

    Ok((header, payload, signature))
}

pub fn encode_jws(
    header: &Header,
    payload: &[u8],
    signature: &[u8],
) -> Result<String, serde_json::Error> {
    let header = URL_SAFE_NO_PAD.encode(serde_json::to_vec(header)?);
    let payload = URL_SAFE_NO_PAD.encode(payload);
    let signature = URL_SAFE_NO_PAD.encode(signature);

    Ok(format!("{}.{}.{}", header, payload, signature))
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Jws {
    pub header: Header,
    pub claims: Vec<u8>,
    pub signature: Vec<u8>,
}

impl Serialize for Jws {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let jws = encode_jws(&self.header, &self.claims, &self.signature).unwrap();
        serializer.serialize_str(&jws)
    }
}

pub struct VerifiedJws {
    pub(crate) header: Header,
    pub(crate) claims: Claims,
    pub(crate) signature: Signature,
    pub(crate) token: String,
}

impl VerifiedJws {
    pub fn claims(&self) -> &Claims {
        &self.claims
    }
    pub fn header(&self) -> &Header {
        &self.header
    }
    pub fn signature(&self) -> &Signature {
        &self.signature
    }
    pub fn token(&self) -> &str {
        &self.token
    }
}

impl AsRef<str> for VerifiedJws {
    fn as_ref(&self) -> &str {
        &self.token
    }
}

impl Into<String> for VerifiedJws {
    fn into(self) -> String {
        self.token
    }
}
