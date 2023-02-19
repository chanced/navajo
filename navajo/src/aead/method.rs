use serde::{Deserialize, Serialize};

use crate::{error::MalformedError, keyring::KEY_ID_LEN};

use super::{Algorithm, Segment};

/// First byte of encrypted data which indicates the method of encryption.
#[derive(Debug, Clone, Serialize, Deserialize, Copy, PartialEq, Eq)]
#[serde(try_from = "u8", into = "u8")]
pub enum Method {
    /// Online with constant memory while making a single left-to-right pass
    ///
    /// Header wireformat is:
    ///
    /// ```plaintext
    /// || Method (1) || Key Id (4) || Nonce (variable) ||
    /// ```
    /// where `Nonce` is the length of the algorithm's nonce.
    Online,
    /// streamed with a constant segment size using the STREAM method as described by
    /// [Online Authenticated-Encryption and its Nonce-Reuse Misuse-Resistance](https://eprint.iacr.org/2015/189.pdf)
    ///
    /// Header wireformat is:
    /// ```plaintext
    /// || Method (1) || Key Id (4) || Salt (variable) || Nonce Prefix (variable) ||
    /// ```
    /// where `Salt` is the length of the algorithm's key and `Nonce Prefix` is the length of the
    /// algorithm's nonce minus 4 bytes for the segment counter 1 byte for the last-block flag.
    StreamingHmacSha256(Segment),
}
impl Method {
    pub fn is_online(self) -> bool {
        matches!(self, Method::Online)
    }

    pub fn is_stream(self) -> bool {
        matches!(self, Method::StreamingHmacSha256(_))
    }

    pub fn header_len(&self, algorithm: Algorithm) -> usize {
        match self {
            // method + key id + nonce
            Method::Online => Method::LEN + KEY_ID_LEN + algorithm.nonce_len(),
            // method + key id + salt + nonce prefix
            Method::StreamingHmacSha256(_) => {
                Method::LEN + KEY_ID_LEN + algorithm.key_len() + algorithm.nonce_prefix_len()
            }
        }
    }
    pub fn to_be_bytes(self) -> [u8; 1] {
        [u8::from(self)]
    }
    pub(super) const LEN: usize = 1;
}

impl From<Method> for u8 {
    fn from(method: Method) -> Self {
        match method {
            Method::Online => 0,
            Method::StreamingHmacSha256(segment) => match segment {
                Segment::FourKilobytes => 1,
                Segment::SixtyFourKilobytes => 2,
                Segment::OneMegabyte => 3,
                Segment::FourMegabytes => 4,
            },
        }
    }
}
impl PartialEq<u8> for Method {
    fn eq(&self, other: &u8) -> bool {
        u8::from(*self) == *other
    }
}
impl PartialEq<Method> for u8 {
    fn eq(&self, other: &Method) -> bool {
        *self == u8::from(*other)
    }
}
impl From<Method> for usize {
    fn from(method: Method) -> Self {
        u8::from(method) as usize
    }
}

impl TryFrom<u8> for Method {
    type Error = MalformedError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Method::Online),
            1 => Ok(Method::StreamingHmacSha256(Segment::FourKilobytes)),
            2 => Ok(Method::StreamingHmacSha256(Segment::SixtyFourKilobytes)),
            3 => Ok(Method::StreamingHmacSha256(Segment::OneMegabyte)),
            4 => Ok(Method::StreamingHmacSha256(Segment::FourMegabytes)),
            _ => Err("missing or unknown encryption method".into()),
        }
    }
}
