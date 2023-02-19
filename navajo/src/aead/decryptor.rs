use alloc::vec::IntoIter;

use super::{
    nonce::{Nonce, NonceSequence},
    Material,
};
use crate::{
    error::DecryptError,
    hkdf::{self, Salt},
    key::Key,
    Buffer,
};

use super::{cipher::Cipher, nonce::NonceOrNonceSequence, Aead, Algorithm, Method};

pub struct Decryptor<K, B>
where
    K: AsRef<Aead>,
{
    aead: K,
    buf: B,
    key_id: Option<u32>,
    key: Option<Key<Material>>,
    nonce: Option<NonceOrNonceSequence>,
    cipher: Option<Cipher>,
    method: Option<Method>,
}

impl<K, B> Decryptor<K, B>
where
    K: AsRef<Aead>,
    B: Buffer,
{
    pub fn new(aead: K, buf: B) -> Self {
        Self {
            aead,
            buf,
            key: None,
            key_id: None,
            nonce: None,
            cipher: None,
            method: None,
        }
    }
    pub fn algorithm(&self) -> Option<Algorithm> {
        self.key.as_ref().map(|c| c.algorithm())
    }
    pub fn update(&mut self, ciphertext: &[u8]) {
        self.buf.extend_from_slice(ciphertext);
    }

    pub fn next(&mut self, additional_data: &[u8]) -> Result<Option<B>, DecryptError> {
        if self.buf.is_empty() {
            return Ok(None);
        }
        if !self.header_is_complete() {
            self.parse_header(additional_data)?;
        }
        if self.cipher.is_none() {
            return Ok(None);
        }
        let seg_end = self.next_segment_end();
        if seg_end.is_none() {
            return Ok(None);
        }
        let seg_end = seg_end.unwrap();
        let nonce = match self.nonce.as_mut().unwrap() {
            NonceOrNonceSequence::Nonce(_) => {
                unreachable!("nonce must be a nonce sequence for streams")
            }
            NonceOrNonceSequence::NonceSequence(seq) => seq.next()?,
        };
        let mut data = self.extract_segment(seg_end);
        self.cipher
            .as_ref()
            .unwrap()
            .decrypt_in_place(nonce, additional_data, &mut data)?;

        Ok(Some(data))
    }
    pub fn finalize(mut self, additional_data: &[u8]) -> Result<IntoIter<B>, DecryptError> {
        if !self.header_is_complete() {
            self.parse_header(additional_data)?;
        }
        let method = self.method.ok_or(DecryptError::EmptyCiphertext)?;
        if method.is_online() {
            let cipher = self.cipher.ok_or(DecryptError::Unspecified)?;
            let nonce = match self.nonce.ok_or(DecryptError::Unspecified)? {
                NonceOrNonceSequence::Nonce(nonce) => Ok(nonce),
                NonceOrNonceSequence::NonceSequence(_) => Err(DecryptError::Unspecified),
            }?;
            cipher.decrypt_in_place(nonce, additional_data, &mut self.buf)?;
            Ok(vec![self.buf].into_iter())
        } else {
            let mut segments = Vec::new();
            while let Some(segment) = self.next(additional_data)? {
                segments.push(segment);
            }
            let cipher = self.cipher.ok_or(DecryptError::Unspecified)?;
            let nonce_seq = match self.nonce.ok_or(DecryptError::Unspecified)? {
                NonceOrNonceSequence::NonceSequence(seq) => Ok(seq),
                NonceOrNonceSequence::Nonce(_) => Err(DecryptError::Unspecified),
            }?;
            cipher.decrypt_in_place(nonce_seq.last()?, additional_data, &mut self.buf)?;
            segments.push(self.buf);
            Ok(segments.into_iter())
        }
    }

    fn extract_segment(&mut self, end: usize) -> B {
        let mut buf = self.buf.split_off(end);
        core::mem::swap(&mut self.buf, &mut buf);
        buf
    }
    fn next_segment_end(&self) -> Option<usize> {
        self.method.and_then(|method| match method {
            Method::Online => None,
            Method::StreamingHmacSha256(segment) => {
                let algorithm = self.algorithm()?;
                if self.counter() == 0 {
                    let last = segment - algorithm.streaming_header_len();

                    if self.buf.len() < last {
                        None
                    } else {
                        Some(last)
                    }
                } else if self.buf.len() > segment {
                    // inetntionally checking for > instead of >= to allow
                    // for the last segment to be finalized
                    Some(segment.into())
                } else {
                    None
                }
            }
        })
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
                self.key = Some(self.aead.as_ref().keyring.get(key_id)?.clone());
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
                    .map_err(|_| DecryptError::Unspecified)?;
                self.nonce = Some(NonceOrNonceSequence::Nonce(nonce));

                Ok(Some(idx + algorithm.nonce_len()))
            }
            Method::StreamingHmacSha256(_) => {
                if buf.len() < idx + algorithm.nonce_prefix_len() {
                    return Ok(None);
                }
                let nonce_prefix = &buf[idx..idx + algorithm.nonce_prefix_len()];
                let nonce_seq = NonceSequence::new_with_prefix(algorithm.nonce_len(), nonce_prefix)
                    .map_err(|_| DecryptError::Unspecified)?;
                self.nonce = Some(NonceOrNonceSequence::NonceSequence(nonce_seq));
                Ok(Some(idx + algorithm.nonce_prefix_len()))
            }
        }
    }
    fn parse_method(&mut self) -> Result<Option<usize>, DecryptError> {
        if self.buf.is_empty() {
            return Ok(None);
        }
        let method: Method = self.buf.as_ref()[0].try_into()?;
        self.method = Some(method);

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
                let key_len = key.len();
                if buf.len() < idx + key_len {
                    None
                } else {
                    let salt = &buf[idx..idx + key_len];
                    let derived_key = self.derive_key(salt, aad);
                    self.cipher = Some(Cipher::new(algorithm, &derived_key));
                    Some(idx + key_len)
                }
            }
        }
    }

    fn derive_key(&self, salt: &[u8], aad: &[u8]) -> Vec<u8> {
        let key = self.key.as_ref().unwrap();
        let salt = Salt::new(hkdf::Algorithm::HkdfSha256, salt);
        let prk = salt.extract(key.material().bytes());
        let mut derived_key = vec![0u8; key.len()];
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

    use crate::{
        aead::{Encryptor, Segment},
        rand,
    };

    use super::*;
    #[test]
    fn test_parsing_online_header() {
        let method = Method::Online;
        let aead = Aead::new(Algorithm::Aes128Gcm, None);
        let key = aead.keyring.primary_key();
        let key_id = key.id();
        let mut nonce = vec![0u8; key.nonce_len()];
        crate::rand::fill(&mut nonce);
        let buf = [
            &method.to_be_bytes()[..],
            &key_id.to_be_bytes()[..],
            &nonce[..],
        ]
        .concat();
        let mut dec = Decryptor::new(&aead, buf);
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
    #[test]
    fn test_parsing_streaming_header() {
        let method = Method::StreamingHmacSha256(Segment::FourMegabytes);
        let aead = Aead::new(Algorithm::Aes128Gcm, None);
        let key_id = aead.primary_key().id;
        let mut seed = vec![0u8; aead.primary_key().algorithm.key_len()];
        rand::fill(&mut seed);
        let mut nonce = vec![0u8; aead.primary_key().algorithm.nonce_prefix_len()];
        crate::rand::fill(&mut nonce);
        let buf = [
            &method.to_be_bytes()[..],
            &key_id.to_be_bytes()[..],
            &seed[..],
            &nonce[..],
        ]
        .concat();
        let mut dec = Decryptor::new(aead, buf);

        dec.next(&[]).unwrap();
        assert_eq!(dec.method, Some(method));
        assert_eq!(dec.key_id, Some(key_id));

        assert!(dec.nonce.is_some());

        let n = dec.nonce.as_ref().unwrap();
        match n {
            NonceOrNonceSequence::Nonce(_) => {
                panic!("expected nonce nonce sequence, got nonce");
            }
            NonceOrNonceSequence::NonceSequence(n) => {
                assert_eq!(
                    n.bytes(),
                    &[&nonce[..], &0u32.to_be_bytes()[..], &[0]].concat()
                );
            }
        }
        assert!(dec.cipher.is_some());
        assert!(dec.key.is_some());
        assert!(dec.buf.is_empty());
    }

    #[test]
    fn test_one_shot() {
        let aead = Aead::new(Algorithm::Aes128Gcm, None);
        let mut data = vec![0u8; 1024];
        rand::fill(&mut data);
        let encryptor = Encryptor::new(&aead, None, data.clone());
        let ciphertext = encryptor.finalize(&[]).unwrap().next().unwrap();
        let decryptor = Decryptor::new(&aead, ciphertext);
        let result = decryptor.finalize(&[]).unwrap().next().unwrap();
        assert_eq!(result, data);
    }
    #[test]
    fn test_streaming() {
        let algorithm = Algorithm::Aes128Gcm;
        let aead = Aead::new(Algorithm::Aes128Gcm, None);
        let mut data = vec![0u8; 65536];
        rand::fill(&mut data);
        let encryptor = Encryptor::new(&aead, Some(Segment::FourKilobytes), data.clone());
        let enc_seg: Vec<Vec<u8>> = encryptor.finalize(&[]).unwrap().collect();
        let ciphertext = enc_seg.concat();
        let decryptor = Decryptor::new(&aead, ciphertext);
        let result: Vec<Vec<u8>> = decryptor.finalize(&[]).unwrap().collect();
        assert_eq!(result.len(), 17);
        let mut remaining: usize = 65536;
        for (i, r) in result.iter().enumerate() {
            if i == 0 {
                assert_eq!(
                    r.len(),
                    4096 - algorithm.streaming_header_len() - algorithm.tag_len()
                );
                remaining -= r.len();
            } else if i < result.len() - 1 {
                assert_eq!(r.len(), 4096 - algorithm.tag_len());
                remaining -= r.len();
            } else {
                assert_eq!(r.len(), remaining);
            }
        }
        assert_eq!(result.concat(), data);
    }
    #[cfg(feature = "ring")]
    #[test]
    fn test_online() {
        let aead = Aead::new(Algorithm::Aes256Gcm, None);
        let unbound_key = ring::aead::UnboundKey::new(
            &ring::aead::AES_256_GCM,
            aead.keyring.primary_key().material().bytes(),
        )
        .unwrap();
        let ring_key = ring::aead::LessSafeKey::new(unbound_key);

        let nonce = Nonce::new_from_slice(
            12,
            &[127, 167, 243, 154, 198, 60, 245, 217, 172, 30, 129, 114],
        )
        .unwrap();

        let mut msg = b"hello world".to_vec();
        ring_key
            .seal_in_place_append_tag(
                nonce.clone().into(),
                ring::aead::Aad::from(b"additional data"),
                &mut msg,
            )
            .unwrap();

        let mut enc = Encryptor::new(&aead, None, b"hello world".to_vec());
        enc.nonce = Some(nonce.clone());
        let ciphertext = enc.finalize(b"additional data").unwrap().next().unwrap();
        assert_eq!(ciphertext[Algorithm::Aes256Gcm.online_header_len()..], msg);
        let aad = b"additional data";
        let mut dec = Decryptor::new(&aead, ciphertext);
        assert!(dec.parse_header(aad).unwrap());
        assert_eq!(dec.method, Some(Method::Online));
        assert_eq!(dec.key_id, Some(aead.primary_key().id));
        assert_eq!(dec.nonce, Some(NonceOrNonceSequence::Nonce(nonce)));

        let result = dec.finalize(aad).unwrap().next().unwrap();
        assert_eq!(result, b"hello world");
    }
}
