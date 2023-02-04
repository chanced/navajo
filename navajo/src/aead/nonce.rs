use crate::{rand, NonceSequenceError, UnspecifiedError, KEY_ID_LEN};

use super::{header::HeaderNonce, Algorithm};

#[derive(Clone, Debug)]
pub(super) struct Nonce(pub(super) Vec<u8>);
impl Nonce {
    pub(super) fn new(algorithm: Algorithm, is_prefix: bool) -> Result<Self, UnspecifiedError> {
        let len = if is_prefix {
            algorithm.nonce_prefix_len()
        } else {
            algorithm.nonce_len()
        };
        let mut val = vec![0; len];
        rand::fill(&mut val)?;
        Ok(Nonce(val))
    }
    pub(super) fn len(&self) -> usize {
        self.0.len()
    }
    pub(super) fn prefix(&self) -> HeaderNonce {
        HeaderNonce::Prefix(&self.0[..KEY_ID_LEN - 1])
    }
}
impl<'a> From<HeaderNonce<'a>> for Nonce {
    fn from(value: HeaderNonce<'a>) -> Self {
        match value {
            HeaderNonce::Full(nonce) => nonce.clone().into_owned(),
            HeaderNonce::Prefix(prefix) => Nonce(prefix.to_vec()),
        }
    }
}
impl TryFrom<Nonce> for ring::aead::Nonce {
    type Error = crate::UnspecifiedError;
    fn try_from(value: Nonce) -> Result<Self, Self::Error> {
        Self::try_assume_unique_for_key(&value.0).map_err(|_| crate::UnspecifiedError)
    }
}
impl TryFrom<&Nonce> for ring::aead::Nonce {
    type Error = crate::UnspecifiedError;
    fn try_from(value: &Nonce) -> Result<Self, Self::Error> {
        Self::try_assume_unique_for_key(&value.0).map_err(|_| crate::UnspecifiedError)
    }
}

impl From<&[u8]> for Nonce {
    fn from(value: &[u8]) -> Self {
        Nonce(value.to_vec())
    }
}
impl AsRef<[u8]> for Nonce {
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}

#[derive(Debug)]
pub(super) struct NonceSequence {
    prefix: Vec<u8>,
    counter: u32,
}

impl NonceSequence {
    pub(super) fn new(algorithm: super::Algorithm) -> Result<Self, UnspecifiedError> {
        let mut prefix = Vec::with_capacity(algorithm.nonce_len() - KEY_ID_LEN - 1);
        crate::rand::fill(&mut prefix)?;

        Ok(Self { prefix, counter: 0 })
    }
    pub(crate) fn counter(&self) -> u32 {
        self.counter
    }
    // pub(crate) fn prefix(&self) -> Nonce {
    //     Nonce(self.prefix.clone().into())
    // }
    pub(super) fn advance(&mut self, is_final: bool) -> Result<(u32, Nonce), NonceSequenceError> {
        if self.counter == u32::MAX {
            return Err(NonceSequenceError::CounterLimitExceeded);
        }
        let mut nonce = self.prefix.clone();
        nonce.reserve(5);
        nonce.extend(&self.counter.to_be_bytes());
        nonce.push(if is_final { 1 } else { 0 });
        let current = self.counter;
        self.counter += 1;
        Ok((current, Nonce(nonce.into())))
    }
}

impl From<Vec<u8>> for NonceSequence {
    fn from(value: Vec<u8>) -> Self {
        Self {
            prefix: value,
            counter: 0,
        }
    }
}
