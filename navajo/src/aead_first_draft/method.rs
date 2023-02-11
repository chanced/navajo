use std::mem;

use serde::{Deserialize, Serialize};

use crate::{DecryptError, MalformedError, KEY_ID_LEN};

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
    /// || Method (1) || KeyID (4) || Nonce (Algorithm Nonce) ||
    /// ```
    Online,
    /// streamed with a constant segment size using the STREAM method as described by
    /// [Online Authenticated-Encryption and its Nonce-Reuse Misuse-Resistance](https://eprint.iacr.org/2015/189.pdf)
    ///
    /// Header wireformat is:
    /// ```plaintext
    /// || Method (1) || KeyID (4) || Salt (Algorithm Key) || Nonce Prefix (Algorithm Nonce Prefix) ||
    StreamHmacSha256(Segment),
}
impl Method {
    pub fn is_online(self) -> bool {
        matches!(self, Method::Online)
    }

    pub fn is_stream(self) -> bool {
        matches!(self, Method::StreamHmacSha256(_))
    }

    pub(super) fn header_len(&self, algorithm: Algorithm) -> usize {
        match self {
            // method + key id + nonce
            Method::Online => Method::len() + KEY_ID_LEN + algorithm.nonce_len(),
            // method + key id + salt + nonce prefix
            Method::StreamHmacSha256(_) => {
                Method::len() + KEY_ID_LEN + algorithm.key_len() + algorithm.nonce_prefix_len()
            }
        }
    }
    pub(super) fn len() -> usize {
        1
    }
}

impl From<Method> for u8 {
    fn from(method: Method) -> Self {
        match method {
            Method::Online => 0,
            Method::StreamHmacSha256(segment) => match segment {
                Segment::FourKB => 1,
                Segment::OneMB => 2,
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
            1 => Ok(Method::StreamHmacSha256(Segment::FourKB)),
            2 => Ok(Method::StreamHmacSha256(Segment::OneMB)),
            _ => Err("missing or unknown encryption method".into()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse() {}
}
