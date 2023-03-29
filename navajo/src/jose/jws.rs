use crate::error::DecodeError;
use base64::engine::{general_purpose::URL_SAFE_NO_PAD, Engine};
use serde::{de::DeserializeOwned, Serialize};

use super::Header;

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

// use crate::error::MalformedError;
// use alloc::borrow::Cow;
// use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
// use serde::{de::DeserializeOwned, Deserialize, Serialize};

// use super::{Header, Verify};

// #[derive(Debug, Clone, Serialize)]
// #[serde(into = "String")]
// pub struct Jws<'a, P>
// where
//     P: Verify + Serialize + DeserializeOwned + Clone + core::fmt::Debug,
// {
//     header: Header,
//     payload: P,
//     signature: Cow<'a, [u8]>,
//     #[serde(skip)]
//     encoded: String,
// }
// impl<P> Jws<'static, P>
// where
//     P: Verify + Serialize + DeserializeOwned + Clone + core::fmt::Debug,
// {
//     pub fn from_str(jws: &str) -> Result<Self, MalformedError> {
//         Self::try_from(jws)
//     }
// }
// impl<'a, P> Jws<'a, P>
// where
//     P: Verify + Serialize + DeserializeOwned + Clone + core::fmt::Debug,
// {
//     pub fn new(header: Header, payload: P, signature: &'a [u8]) -> Result<Self, MalformedError> {
//         let cached = Self::gen_cache(&header, &payload, &signature)?;
//         let signature = Cow::Borrowed(signature);
//         Ok(Self {
//             header,
//             payload,
//             signature,
//             encoded: cached,
//         })
//     }

//     // pub fn from_bytes(jws: &[u8]) -> Result<Self, JwsError<P>> {
//     //     Self::try_from(jws)
//     // }

//     pub fn header(&self) -> &Header {
//         &self.header
//     }
//     pub fn payload(&self) -> &P {
//         &self.payload
//     }

//     pub fn signature(&self) -> &[u8] {
//         &self.signature
//     }

//     pub fn as_str(&self) -> &str {
//         self.encoded.as_str()
//     }

//     fn gen_cache(header: &Header, payload: &P, signature: &[u8]) -> Result<String, MalformedError> {
//         let header = URL_SAFE_NO_PAD.encode(serde_json::to_vec(header)?);
//         let payload = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&payload)?);
//         let signature = URL_SAFE_NO_PAD.encode(signature);
//         Ok(format!("{}.{}.{}", header, payload, signature))
//     }
// }

// impl<P> AsRef<str> for Jws<'_, P>
// where
//     P: Verify + Serialize + DeserializeOwned + Clone + core::fmt::Debug,
// {
//     fn as_ref(&self) -> &str {
//         self.encoded.as_str()
//     }
// }

// impl<'de, P> Deserialize<'de> for Jws<'static, P>
// where
//     P: Verify + Serialize + DeserializeOwned + Clone + core::fmt::Debug,
// {
//     fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
//     where
//         D: serde::Deserializer<'de>,
//     {
//         let jws = String::deserialize(deserializer)?;
//         Self::try_from(jws.as_str()).map_err(serde::de::Error::custom)
//     }
// }
// impl<P> core::fmt::Display for Jws<'_, P>
// where
//     P: Verify + Serialize + DeserializeOwned + Clone + core::fmt::Debug,
// {
//     fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
//         write!(f, "{}", self.encoded)
//     }
// }

// impl<P> From<Jws<'_, P>> for (P, Header)
// where
//     P: Verify + Serialize + DeserializeOwned + Clone + core::fmt::Debug,
// {
//     fn from(jws: Jws<P>) -> Self {
//         (jws.payload, jws.header)
//     }
// }

// impl<P> From<Jws<'_, P>> for String
// where
//     P: Verify + Serialize + DeserializeOwned + Clone + core::fmt::Debug,
// {
//     fn from(jws: Jws<P>) -> Self {
//         jws.to_string()
//     }
// }

// impl<P> From<&Jws<'_, P>> for String
// where
//     P: Verify + Serialize + DeserializeOwned + Clone + core::fmt::Debug,
// {
//     fn from(jws: &Jws<P>) -> Self {
//         jws.to_string()
//     }
// }

// impl<P> TryFrom<String> for Jws<'_, P>
// where
//     P: Verify + Serialize + DeserializeOwned + Clone + core::fmt::Debug,
// {
//     type Error = MalformedError;
//     fn try_from(jws: String) -> Result<Self, Self::Error> {
//         Self::try_from(jws.as_str())
//     }
// }
// impl<P> TryFrom<&String> for Jws<'static, P>
// where
//     P: Verify + Serialize + DeserializeOwned + Clone + core::fmt::Debug,
// {
//     type Error = MalformedError;
//     fn try_from(jws: &String) -> Result<Self, Self::Error> {
//         Self::try_from(jws.as_str())
//     }
// }
// impl<P> TryFrom<&str> for Jws<'static, P>
// where
//     P: Verify + Serialize + DeserializeOwned + Clone + core::fmt::Debug,
// {
//     type Error = MalformedError;
//     fn try_from(jws: &str) -> Result<Self, Self::Error> {

//     }
// }
