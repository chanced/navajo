use ring::error::Unspecified;

use super::{
    algorithm,
    nonce::{Nonce, NonceSequence},
    Material,
};
use crate::{
    error::DecryptError,
    hkdf::{self, Salt},
    key::Key,
    keyring::KEY_ID_LEN,
    Buffer,
};

use super::{cipher::Cipher, nonce::NonceOrNonceSequence, Aead, Algorithm, Method, Segment};

pub struct Decrypt<B> {
    aead: Aead,
    buf: B,
    key_id: Option<u32>,
    key: Option<Key<Material>>,
    segment: Option<Segment>,
    nonce: Option<NonceOrNonceSequence>,
    cipher: Option<Cipher>,
    method: Option<Method>,
}

impl<B> Decrypt<B>
where
    B: Buffer,
{
    pub fn new(aead: &Aead, buf: B) -> Self {
        Self {
            aead: aead.clone(),
            buf,
            key: None,
            key_id: None,
            segment: None,
            nonce: None,
            cipher: None,
            method: None,
        }
    }
    pub fn algorithm(&self) -> Option<Algorithm> {
        self.key.as_ref().map(|c| c.algorithm())
    }
    pub fn update(
        &mut self,
        additional_data: &[u8],
        ciphertext: &[u8],
    ) -> Result<Option<Vec<B>>, DecryptError> {
        self.buf.extend_from_slice(ciphertext);
        let mut results = vec![];
        while let Some(segment) = self.next(additional_data)? {
            results.push(segment);
        }
        if results.is_empty() {
            Ok(None)
        } else {
            Ok(Some(results))
        }
    }

    fn next(&mut self, aad: &[u8]) -> Result<Option<B>, DecryptError> {
        if self.buf.is_empty() {
            return Ok(None);
        }
        if !self.header_is_complete() {
            self.parse_header(aad)?;
        }
        if self.cipher.is_none() {
            return Ok(None);
        }
        Ok(None)
    }

    fn header_is_complete(&self) -> bool {
        if self.key_id.is_none() {
            return false;
        }
        if self.method.is_none() {
            return false;
        }
        let method = self.method.unwrap();
        match method {
            Method::Online => self.nonce.is_some(),
            Method::StreamingHmacSha256(_) => self.nonce.is_some() && self.cipher.is_some(),
        }
    }

    fn parse_header(&mut self, aad: &[u8]) -> Result<bool, DecryptError> {
        let mut idx = 0;
        let method: Method;
        if let Some(parsed_method) = self.method {
            method = parsed_method;
        } else if let Some(i) = self.parse_method()? {
            idx = i;
            method = self.method.unwrap();
        } else {
            return Ok(false);
        }

        if self.key_id.is_none() {
            if let Some((i, key_id)) = self.parse_key_id(idx) {
                idx = i;
                self.key = Some(self.aead.keyring.get(key_id)?.clone());
            } else {
                self.move_cursor(idx);
                return Ok(false);
            }
        }
        let key = self.key.clone().unwrap();
        if self.cipher.is_none() {
            if let Some(i) = self.parse_cipher(idx, &key, method, aad) {
                idx = i;
            } else {
                self.move_cursor(idx);
                return Ok(false);
            }
        }
        if self.nonce.is_none() {
            return if let Some(i) = self.parse_nonce(idx, method, key.algorithm())? {
                idx = i;
                self.move_cursor(idx);
                Ok(true)
            } else {
                Ok(false)
            };
        }
        Ok(true)
    }

    fn move_cursor(&mut self, idx: usize) {
        if idx > 0 {
            let mut buf = self.buf.split_off(idx);
            std::mem::swap(&mut buf, &mut self.buf);
        }
    }

    fn parse_nonce(
        &mut self,
        idx: usize,
        method: Method,
        algorithm: Algorithm,
    ) -> Result<Option<usize>, DecryptError> {
        let buf = self.buf.as_ref();
        match method {
            Method::Online => {
                if buf.len() < idx + algorithm.nonce_len() {
                    return Ok(None);
                }
                let nonce = &buf[idx..idx + algorithm.nonce_len()];
                let nonce = Nonce::new_from_slice(algorithm.nonce_len(), nonce)
                    .map_err(|e| DecryptError::Malformed(e.to_string().into()))?;
                self.nonce = Some(NonceOrNonceSequence::Nonce(nonce));

                Ok(Some(idx + algorithm.nonce_len()))
            }
            Method::StreamingHmacSha256(_) => {
                if buf.len() < idx + algorithm.nonce_prefix_len() {
                    return Ok(None);
                }
                let nonce_prefix = &buf[idx..idx + algorithm.nonce_prefix_len()];
                let nonce_seq =
                    NonceSequence::new_with_prefix(algorithm.nonce_prefix_len(), nonce_prefix)
                        .map_err(|e| DecryptError::Malformed(e.to_string().into()))?;
                self.nonce = Some(NonceOrNonceSequence::NonceSequence(nonce_seq));
                Ok(Some(algorithm.nonce_prefix_len()))
            }
        }
    }
    fn parse_method(&mut self) -> Result<Option<usize>, DecryptError> {
        if self.buf.is_empty() {
            return Ok(None);
        }
        self.method = Some(self.buf.as_ref()[0].try_into()?);
        Ok(Some(Method::LEN))
    }

    fn parse_key_id(&mut self, idx: usize) -> Option<(usize, u32)> {
        let buf = self.buf.as_ref();
        if buf.len() < idx + 4 {
            return None;
        }
        let key_id = u32::from_be_bytes([buf[idx], buf[idx + 1], buf[idx + 2], buf[idx + 3]]);
        self.key_id = Some(key_id);

        Some((idx + 4, key_id))
    }
    fn parse_cipher(
        &mut self,
        idx: usize,
        key: &Key<Material>,
        method: Method,
        aad: &[u8],
    ) -> Option<usize> {
        let buf = self.buf.as_ref();
        let algorithm = self.algorithm().unwrap();
        match method {
            Method::Online => {
                self.cipher = Some(Cipher::new(algorithm, key.bytes()));
                Some(idx)
            }
            Method::StreamingHmacSha256(_) => {
                if buf.len() < idx + KEY_ID_LEN {
                    None
                } else {
                    let salt = &buf[idx..idx + KEY_ID_LEN];
                    let derived_key = self.derive_key(salt, aad);
                    self.cipher = Some(Cipher::new(algorithm, &derived_key));
                    Some(idx + KEY_ID_LEN)
                }
            }
        }
    }

    fn derive_key(&self, salt: &[u8], aad: &[u8]) -> Vec<u8> {
        let key = self.key.as_ref().unwrap();
        let salt = Salt::new(hkdf::Algorithm::HkdfSha256, salt);
        let prk = salt.extract(key.material().bytes());
        let mut derived_key = vec![0u8; key.algorithm().key_len()];
        prk.expand(&[aad], &mut derived_key).unwrap(); // safety: key is always an appropriate length
        derived_key
    }

    pub fn counter(&self) -> u32 {
        self.nonce.as_ref().map_or(0, |n| match n {
            NonceOrNonceSequence::Nonce(_) => 0,
            NonceOrNonceSequence::NonceSequence(n) => n.counter(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_parsing_header() {
        let method = Method::Online;
        let aead = Aead::new(Algorithm::Aes128Gcm, None);
        let key_id = aead.primary_key().id;
        let mut nonce = vec![0u8; aead.primary_key().algorithm.nonce_len()];
        crate::rand::fill(&mut nonce);
        let buf = [
            &method.to_be_bytes()[..],
            &key_id.to_be_bytes()[..],
            &nonce[..],
        ]
        .concat();
        let mut dec = Decrypt::new(&aead, buf);
        dec.next(&[]).unwrap();
        assert_eq!(dec.method, Some(method));
        assert_eq!(dec.key_id, Some(key_id));
        assert!(dec.nonce.is_some());

        let n = dec.nonce.as_ref().unwrap();
        match n {
            NonceOrNonceSequence::Nonce(n) => {
                assert_eq!(n.bytes(), &nonce[..]);
            }
            NonceOrNonceSequence::NonceSequence(_) => {
                panic!("expected nonce, got nonce sequence");
            }
        }
        assert!(dec.cipher.is_some());
        assert!(dec.key.is_some());
        assert!(dec.buf.is_empty());
    }
}
