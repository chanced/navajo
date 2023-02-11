use std::{
    borrow::Cow,
    io::{Cursor, Error},
    sync::Arc,
};

use crate::error::{HeaderError, MalformedError};
use crate::KEY_ID_LEN;

use super::{algorithm, nonce::Nonce, salt::Salt, Algorithm, Key, Method};

#[derive(Clone, Debug)]
pub(super) enum HeaderNonce<'a> {
    Full(Cow<'a, Nonce>),
    Prefix(&'a [u8]),
}
impl<'a> HeaderNonce<'a> {
    pub(super) fn len(&self) -> usize {
        match self {
            HeaderNonce::Full(nonce) => nonce.len(),
            HeaderNonce::Prefix(prefix) => prefix.len(),
        }
    }
    pub(super) fn as_ref(&self) -> &[u8] {
        match self {
            HeaderNonce::Full(nonce) => nonce.0.as_ref(),
            HeaderNonce::Prefix(prefix) => prefix,
        }
    }
}
impl From<Nonce> for HeaderNonce<'_> {
    fn from(value: Nonce) -> Self {
        HeaderNonce::Full(Cow::Owned(value))
    }
}
impl<'a> From<&'a Nonce> for HeaderNonce<'a> {
    fn from(value: &'a Nonce) -> Self {
        HeaderNonce::Full(Cow::Borrowed(value))
    }
}
pub(super) struct PartialHeader {
    pub(super) method: Option<Method>,
    pub(super) key_id: Option<u32>,
    pub(super) nonce: Option<HeaderNonce<'static>>,
    pub(super) salt: Option<Option<Salt>>,
}
impl PartialHeader {
    pub(super) fn new() -> Self {
        PartialHeader {
            method: None,
            key_id: None,
            nonce: None,
            salt: None,
        }
    }
    fn parse(&mut self, data: &[u8]) -> Result<Option<Header>, HeaderError> {}
    fn parse_salt(
        &mut self,
        method: Method,
        algorithm: Algorithm,
        data: &[u8],
    ) -> Result<bool, MalformedError> {
        match method {
            Method::Online => {
                self.salt = Some(None);
            }
            Method::StreamHmacSha256(_) => {
                if data.len() < algorithm.key_len() {
                    return Ok(false);
                }
                // let salt = Salt::new(, &data[..algorithm.key_len()]);
            }
        }
        todo!()
    }
    fn parse_method(&mut self, data: &[u8]) -> Result<bool, MalformedError> {
        if let Some(method) = self.method.clone() {
            return Ok(true); // this should never happen
        }
        if data.is_empty() {
            return Ok(false);
        }
        let method = Method::try_from(data[0])?;
        self.method = Some(method);
        Ok(true)
    }
    fn parse_key_id(&mut self, data: &[u8]) -> Result<bool, MalformedError> {
        if let Some(key_id) = self.key_id.clone() {
            return Ok(true); // this should never happen
        }
        if data.len() < KEY_ID_LEN {
            return Ok(false);
        }
        let key_id = u32::from_be_bytes([data[0], data[1], data[2], data[3]]);
        self.key_id = Some(key_id);
        Ok(true)
    }
    fn parse_nonce(
        &mut self,
        method: Method,
        algorithm: Algorithm,
        data: &[u8],
    ) -> Result<bool, MalformedError> {
        if let Some(nonce) = self.nonce.clone() {
            return Ok(true); // this should never happen
        }
        match method {
            Method::Online => {
                if data.len() < algorithm.nonce_len() {
                    return Ok(false);
                }
                let nonce = Nonce(data[..algorithm.nonce_len()].to_owned());
                self.nonce = Some(HeaderNonce::Full(Cow::Owned(nonce)));
                Ok(true)
            }
            Method::StreamHmacSha256(_) => {
                if data.len() < algorithm.nonce_prefix_len() {
                    return Ok(true);
                }
                let nonce = HeaderNonce::Prefix(&data[..algorithm.nonce_prefix_len()]);
                self.nonce = Some(nonce);
                Ok(true)
            }
        }
    }
}

#[derive(Clone)]
pub(super) struct Header<'a> {
    pub(super) method: Method,
    pub(super) key_id: u32,
    pub(super) nonce: HeaderNonce<'a>,
    pub(super) salt: Option<Salt>,
}
impl<'a> Header<'a> {
    pub(super) fn len(&self) -> usize {
        Method::len()
            + KEY_ID_LEN
            + self.nonce.len()
            + self.salt.as_ref().map_or(0, |salt| salt.bytes.len())
    }
    pub(super) fn write(&self, data: &mut Vec<u8>) {
        data.reserve(self.len());
        data.push(self.method.into());
        data.extend_from_slice(&self.key_id.to_le_bytes());
        if let Some(salt) = self.salt.as_ref() {
            data.extend_from_slice(&salt.bytes);
        }
        data.extend_from_slice(&self.nonce.as_ref());
    }
}

impl<'a> TryFrom<&HeaderNonce<'a>> for ring::aead::Nonce {
    type Error = crate::UnspecifiedError;
    fn try_from(value: &HeaderNonce<'a>) -> Result<Self, Self::Error> {
        Self::try_assume_unique_for_key(value.as_ref()).map_err(|_| crate::UnspecifiedError)
    }
}
