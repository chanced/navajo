use zeroize::ZeroizeOnDrop;

use crate::error::DecryptError;

use super::{cipher::Cipher, nonce::NonceSequence, Aead, Algorithm, Method, Segment};

#[derive(ZeroizeOnDrop)]
pub struct Decrypt {
    aead: Aead,
    buffer: Vec<u8>,
    key_id: Option<u32>,
    #[zeroize(skip)]
    segment: Option<Segment>,
    #[zeroize(skip)]
    nonce_seq: Option<NonceSequence>,
    #[zeroize(skip)]
    cipher: Option<Cipher>,
    #[zeroize(skip)]
    method: Option<Method>,
}

impl Decrypt {
    pub fn new(aead: &Aead) -> Self {
        Self {
            aead: aead.clone(),
            buffer: Vec::new(),
            key_id: None,
            segment: None,
            nonce_seq: None,
            cipher: None,
            method: None,
        }
    }
    pub fn algorithm(&self) -> Option<Algorithm> {
        self.cipher.as_ref().map(|c| c.algorithm())
    }

    pub fn update(&mut self, ciphertext: &[u8]) {
        self.buffer.extend_from_slice(ciphertext);
    }
    fn read_method(&mut self) -> Result<Option<Method>, DecryptError> {
        if self.method.is_some() || self.buffer.is_empty() {
            return Ok(None);
        }
        let method = self.buffer[0].try_into()?;
        Ok(Some(method))
    }
    fn read_key_id(&mut self) -> Result<Option<u32>, DecryptError> {
        if self.key_id.is_some() {
            return Ok(None);
        }
        if self.method.is_some() && self.buffer.len() < 4 {
            return Ok(None);
        }
        if self.method.is_none() && self.buffer.len() < 5 {
            return Ok(None);
        }
        let key_id = u32::from_be_bytes(self.buffer[1..5].try_into().unwrap());
        Ok(Some(key_id))
    }

    pub fn counter(&self) -> usize {
        self.nonce_seq.as_ref().map(|n| n.counter()).unwrap_or(0) as usize
    }
}

#[cfg(test)]
mod tests {}
