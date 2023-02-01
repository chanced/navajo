use std::borrow::Cow;

use bytes::BufMut;

use crate::KEY_ID_LEN;

use super::{nonce::Nonce, salt::Salt, Method};

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
}

impl<'a> TryFrom<&HeaderNonce<'a>> for ring::aead::Nonce {
    type Error = crate::UnspecifiedError;
    fn try_from(value: &HeaderNonce<'a>) -> Result<Self, Self::Error> {
        Self::try_assume_unique_for_key(value.as_ref()).map_err(|_| crate::UnspecifiedError)
    }
}

pub(super) trait HeaderWriter {
    fn put_header(&mut self, header: Header);
}
impl<T: BufMut> HeaderWriter for T {
    fn put_header(&mut self, header: Header) {
        self.put_u8(u8::from(header.method));
        self.put_u32(header.key_id);
        if let Some(salt) = &header.salt {
            self.put_slice(&salt.bytes);
        }
        self.put_slice(header.nonce.as_ref());
    }
}
