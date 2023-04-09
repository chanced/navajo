use core::{fmt::Display, str::FromStr};

use crate::error::DecodeError;
use alloc::{
    borrow::Cow,
    format,
    string::{String, ToString},
    sync::Arc,
    vec::Vec,
};
use base64::engine::{general_purpose::URL_SAFE_NO_PAD, Engine};
use serde::Deserialize;

#[cfg(feature = "dsa")]
use super::{Claims, Header, Jwk};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Jws<T> {
    pub header: Vec<u8>,
    pub payload: Vec<u8>,
    pub signature: T,
}

impl<T> Display for Jws<T>
where
    T: AsRef<[u8]>,
{
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let header = URL_SAFE_NO_PAD.encode(&self.header);
        let payload = URL_SAFE_NO_PAD.encode(&self.payload);
        let signature = URL_SAFE_NO_PAD.encode(self.signature.as_ref());
        write!(f, "{header}.{payload}.{signature}")
    }
}

impl<'de, T> Deserialize<'de> for Jws<T>
where
    T: From<Vec<u8>>,
{
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let jws: String = Deserialize::deserialize(deserializer)?;
        let local = Jws::<Vec<u8>>::from_str(&jws).map_err(serde::de::Error::custom)?;
        Ok(Jws {
            header: local.header,
            payload: local.payload,
            signature: local.signature.into(),
        })
    }
}

impl FromStr for Jws<Vec<u8>> {
    type Err = DecodeError;

    fn from_str(jws: &str) -> Result<Self, Self::Err> {
        let split: Vec<&str> = jws.split('.').collect();
        if split.len() != 3 {
            return Err("malformed jws".into());
        }
        let header: Vec<u8> = URL_SAFE_NO_PAD.decode(split[0])?;
        let payload: Vec<u8> = URL_SAFE_NO_PAD.decode(split[1])?;
        let signature: Vec<u8> = URL_SAFE_NO_PAD.decode(split[2])?;

        Ok(Jws {
            header,
            payload,
            signature,
        })
    }
}
impl TryFrom<String> for Jws<Vec<u8>> {
    type Error = DecodeError;

    fn try_from(jws: String) -> Result<Self, Self::Error> {
        Self::from_str(&jws)
    }
}
impl TryFrom<&String> for Jws<Vec<u8>> {
    type Error = DecodeError;

    fn try_from(jws: &String) -> Result<Self, Self::Error> {
        Self::from_str(jws)
    }
}
impl TryFrom<&str> for Jws<Vec<u8>> {
    type Error = DecodeError;

    fn try_from(jws: &str) -> Result<Self, Self::Error> {
        Self::from_str(jws)
    }
}

impl<T> From<Jws<T>> for String
where
    T: AsRef<[u8]>,
{
    fn from(jws: Jws<T>) -> String {
        let header = URL_SAFE_NO_PAD.encode(&jws.header);
        let payload = URL_SAFE_NO_PAD.encode(&jws.payload);
        let signature = URL_SAFE_NO_PAD.encode(&jws.signature);
        format!("{header}.{payload}.{signature}")
    }
}

#[cfg(feature = "dsa")]
use serde::Serialize;

#[cfg(feature = "dsa")]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedJws<'t> {
    header: Header,
    claims: Claims,
    signature: crate::dsa::Signature,
    token: Cow<'t, str>,
    jwk: Arc<Jwk>,
}
#[cfg(feature = "dsa")]
impl Serialize for VerifiedJws<'_> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&self.token)
    }
}
#[cfg(feature = "dsa")]
impl<'t> VerifiedJws<'t> {
    pub(crate) fn new(
        header: Header,
        claims: Claims,
        signature: crate::dsa::Signature,
        token: Cow<'t, str>,
        jwk: Arc<Jwk>,
    ) -> VerifiedJws<'t> {
        VerifiedJws {
            header,
            claims,
            signature,
            token,
            jwk,
        }
    }

    pub fn take_parts(
        self,
    ) -> (
        Header,
        Claims,
        crate::dsa::Signature,
        Cow<'t, str>,
        Arc<Jwk>,
    ) {
        (
            self.header,
            self.claims,
            self.signature,
            self.token,
            self.jwk,
        )
    }
    pub fn claims(&self) -> &Claims {
        &self.claims
    }
    pub fn header(&self) -> &Header {
        &self.header
    }
    pub fn signature(&self) -> &[u8] {
        &self.signature
    }
    pub fn token(&self) -> &str {
        &self.token
    }
    pub fn jwk(&self) -> &Jwk {
        &self.jwk
    }
}
#[cfg(feature = "dsa")]
impl core::fmt::Display for VerifiedJws<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}", self.token)
    }
}
#[cfg(feature = "dsa")]
impl AsRef<str> for VerifiedJws<'_> {
    fn as_ref(&self) -> &str {
        &self.token
    }
}
#[cfg(feature = "dsa")]
impl From<VerifiedJws<'_>> for String {
    fn from(jws: VerifiedJws) -> Self {
        jws.token.to_string()
    }
}
