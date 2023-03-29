use crate::{dsa::Signature, error::MalformedError};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use serde_json::Value;

use super::Header;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(try_from = "&str", into = "String")]
pub struct Jws<P>
where
    P: Serialize + DeserializeOwned + Clone + core::fmt::Debug,
{
    pub header: Header,
    pub payload: P,
    pub signature: Signature,
}
impl<P> Jws<P>
where
    P: Serialize + DeserializeOwned + Clone + core::fmt::Debug,
{
    pub fn new(header: Header, payload: P, signature: Signature) -> Self {
        Self {
            header,
            payload,
            signature,
        }
    }
}

impl<P> core::fmt::Display for Jws<P>
where
    P: Serialize + DeserializeOwned + Clone + core::fmt::Debug,
{
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let header = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&self.header)?);
        let payload = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&self.payload)?);
        let signature = URL_SAFE_NO_PAD.encode(self.signature.as_bytes());
        write!(f, "{header}.{payload}.{signature}",)
    }
}
impl<P> Jws<P>
where
    P: Serialize + DeserializeOwned + Clone + core::fmt::Debug,
{
    pub fn from_str(jws: &str) -> Result<Self, MalformedError> {
        Self::try_from(jws)
    }
}
impl<P> From<Jws<P>> for String
where
    P: Serialize + DeserializeOwned + Clone + core::fmt::Debug,
{
    fn from(jws: Jws<P>) -> Self {
        jws.to_string()
    }
}

impl<P> From<&Jws<P>> for String
where
    P: Serialize + DeserializeOwned + Clone + core::fmt::Debug,
{
    fn from(jws: &Jws<P>) -> Self {
        jws.to_string()
    }
}
impl<P> TryFrom<String> for Jws<P>
where
    P: Serialize + DeserializeOwned + Clone + core::fmt::Debug,
{
    type Error = MalformedError;
    fn try_from(jws: String) -> Result<Self, Self::Error> {
        Self::try_from(jws.as_str())
    }
}
impl<P> TryFrom<&String> for Jws<P>
where
    P: Serialize + DeserializeOwned + Clone + core::fmt::Debug,
{
    type Error = MalformedError;
    fn try_from(jws: &String) -> Result<Self, Self::Error> {
        Self::try_from(jws.as_str())
    }
}
impl<P> TryFrom<&str> for Jws<P>
where
    P: Serialize + DeserializeOwned + Clone + core::fmt::Debug,
{
    type Error = MalformedError;
    fn try_from(jws: &str) -> Result<Self, Self::Error> {
        // let (header, payload, sig) = decode_jws(jws)?;
        // let header = URL_SAFE_NO_PAD.decode(header.as_bytes());
        // let payload = URL_SAFE_NO_PAD.decode(payload.as_bytes());
        // let signature = URL_SAFE_NO_PAD.decode(sig.as_bytes());
        let split = jws.split('.');
        let header: Vec<u8>;
        let payload: Vec<u8>;
        let signature: Vec<u8>;

        let mut i = 0;
        for part in split {
            let part = URL_SAFE_NO_PAD.decode(part)?;
            match i {
                0 => header = part,
                1 => payload = part,
                2 => signature = part,
                _ => return Err("malformed jws".into()),
            }
            i += 1;
        }
        if i < 2 {
            return Err("malformed jws".into());
        }
        let payload: Value = serde_json::from_slice(&payload)?;
        let header: Header = serde_json::from_slice(&header)?;
        let alg = crate::dsa::Algorithm::try_from(header.algorithm)?;

        let signature = Signature::from_bytes(&signature)?;
        Ok(Jws {
            header,
            payload,
            signature,
        })
    }
}
