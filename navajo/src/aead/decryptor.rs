use super::{
    nonce::{NonceSequence, SingleNonce},
    Material,
};
use crate::{
    error::DecryptError,
    hkdf::{self, Salt},
    key::Key,
    rand::Rng,
    Aad, Aead, Buffer, SystemRng,
};
#[cfg(not(feature = "std"))]
use alloc::vec;
#[cfg(not(feature = "std"))]
use alloc::vec::{IntoIter, Vec};

#[cfg(feature = "std")]
use std::vec::IntoIter;

use super::{cipher::Cipher, nonce::Nonce, Algorithm, Method};

pub struct Decryptor<C, B, G>
where
    C: AsRef<Aead>,
    G: Rng,
{
    cipher: C,
    buf: B,
    key_id: Option<u32>,
    key: Option<Key<Material>>,
    nonce: Option<Nonce>,
    backend: Option<Cipher>,
    method: Option<Method>,
    rng: G,
}

impl<C, B> Decryptor<C, B, SystemRng>
where
    C: AsRef<Aead>,
    B: Buffer,
{
    pub fn new(cipher: C, buf: B) -> Self {
        Self {
            cipher,
            buf,
            key: None,
            key_id: None,
            nonce: None,
            backend: None,
            method: None,
            rng: SystemRng,
        }
    }
}
impl<C, B, G> Decryptor<C, B, G>
where
    C: AsRef<Aead>,
    B: Buffer,
    G: Rng,
{
    #[cfg(test)]
    pub fn new_with_rng(rng: G, cipher: C, buf: B) -> Self {
        Self {
            cipher,
            buf,
            key: None,
            key_id: None,
            nonce: None,
            backend: None,
            method: None,
            rng,
        }
    }
    pub fn algorithm(&self) -> Option<Algorithm> {
        self.key.as_ref().map(|c| c.algorithm())
    }
    pub fn update<A>(&mut self, aad: Aad<A>, ciphertext: &[u8]) -> Result<(), DecryptError>
    where
        A: AsRef<[u8]>,
    {
        self.buf.extend_from_slice(ciphertext);
        if !self.header_is_complete() {
            self.parse_header(aad.as_ref())?;
        }
        Ok(())
    }

    pub fn method(&self) -> Option<Method> {
        self.method
    }
    pub fn key_id(&self) -> Option<u32> {
        self.key_id
    }

    pub fn next<A>(&mut self, aad: Aad<A>) -> Result<Option<B>, DecryptError>
    where
        A: AsRef<[u8]>,
    {
        let aad = aad.as_ref();
        if self.buf.is_empty() {
            return Ok(None);
        }
        if !self.header_is_complete() {
            self.parse_header(aad)?;
        }
        if self.backend.is_none() {
            return Ok(None);
        }
        let seg_end = self.next_segment_end();
        if seg_end.is_none() {
            return Ok(None);
        }
        let seg_end = seg_end.unwrap();
        let nonce = match self.nonce.as_mut().unwrap() {
            Nonce::Single(_) => {
                unreachable!("nonce must be a nonce sequence for streams")
            }
            Nonce::Sequence(seq) => seq.next()?,
        };
        let mut data = self.extract_segment(seg_end);
        self.backend
            .as_ref()
            .unwrap()
            .decrypt_in_place(nonce, aad, &mut data)?;

        Ok(Some(data))
    }
    pub fn finalize<A>(mut self, aad: Aad<A>) -> Result<IntoIter<B>, DecryptError>
    where
        A: AsRef<[u8]>,
    {
        if !self.header_is_complete() {
            self.parse_header(aad.as_ref())?;
        }
        let method = self.method.ok_or(DecryptError::EmptyCiphertext)?;
        if method.is_online() {
            let cipher = self.backend.ok_or(DecryptError::Unspecified)?;
            let nonce = match self.nonce.ok_or(DecryptError::Unspecified)? {
                Nonce::Single(nonce) => Ok(nonce),
                Nonce::Sequence(_) => Err(DecryptError::Unspecified),
            }?;
            cipher.decrypt_in_place(nonce, aad.as_ref(), &mut self.buf)?;
            Ok(vec![self.buf].into_iter())
        } else {
            let mut segments = Vec::new();
            while let Some(segment) = self.next(Aad(aad.as_ref()))? {
                segments.push(segment);
            }
            let cipher = self.backend.ok_or(DecryptError::Unspecified)?;
            let nonce_seq = match self.nonce.ok_or(DecryptError::Unspecified)? {
                Nonce::Sequence(seq) => Ok(seq),
                Nonce::Single(_) => Err(DecryptError::Unspecified),
            }?;
            cipher.decrypt_in_place(nonce_seq.last()?, aad.as_ref(), &mut self.buf)?;
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

    pub fn header_is_complete(&self) -> bool {
        if self.key_id.is_none() {
            return false;
        }
        if self.method.is_none() {
            return false;
        }
        let method = self.method.unwrap();
        match method {
            Method::Online => self.nonce.is_some(),
            Method::StreamingHmacSha256(_) => self.nonce.is_some() && self.backend.is_some(),
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
                self.key = Some(self.cipher.as_ref().keyring.get(key_id)?.clone());
            } else {
                self.move_cursor(idx);
                return Ok(false);
            }
        }
        let key = self.key.clone().unwrap();
        if self.backend.is_none() {
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
                self.move_cursor(idx);
                Ok(false)
            };
        }
        Ok(true)
    }

    fn move_cursor(&mut self, idx: usize) {
        if idx > 0 {
            let mut buf = self.buf.split_off(idx);
            core::mem::swap(&mut buf, &mut self.buf);
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
                let nonce = SingleNonce::new_from_slice(algorithm.nonce_len(), nonce)
                    .map_err(|_| DecryptError::Unspecified)?;
                self.nonce = Some(Nonce::Single(nonce));

                Ok(Some(idx + algorithm.nonce_len()))
            }
            Method::StreamingHmacSha256(_) => {
                if buf.len() < idx + algorithm.nonce_prefix_len() {
                    return Ok(None);
                }
                let nonce_prefix = &buf[idx..idx + algorithm.nonce_prefix_len()];
                let nonce_seq = NonceSequence::new_with_prefix(algorithm.nonce_len(), nonce_prefix)
                    .map_err(|_| DecryptError::Unspecified)?;
                self.nonce = Some(Nonce::Sequence(nonce_seq));
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
                self.backend = Some(key.cipher());
                Some(idx)
            }
            Method::StreamingHmacSha256(_) => {
                let key_len = key.len();
                if buf.len() < idx + key_len {
                    None
                } else {
                    let salt = &buf[idx..idx + key_len];
                    let derived_key = self.derive_key(salt, aad);
                    self.backend = Some(Cipher::new(algorithm, &derived_key));
                    Some(idx + key_len)
                }
            }
        }
    }
    fn derive_key(&self, salt: &[u8], aad: &[u8]) -> Vec<u8> {
        let key = self.key.as_ref().unwrap();
        let salt = Salt::new(hkdf::Algorithm::Sha256, salt);
        let prk = salt.extract(key.material().bytes());
        let mut derived_key = vec![0u8; key.len()];
        prk.expand(&[aad], &mut derived_key).unwrap(); // safety: key is always an appropriate length
        derived_key
    }

    pub fn counter(&self) -> u32 {
        self.nonce.as_ref().map_or(0, |n| match n {
            Nonce::Single(_) => 0,
            Nonce::Sequence(n) => n.counter(),
        })
    }
}

#[cfg(test)]
mod tests {

    use crate::{
        aead::{Encryptor, Segment},
        Aead, SystemRng,
    };

    use super::*;
    #[test]
    fn test_parsing_online_header() {
        let method = Method::Online;
        let aead = Aead::new(Algorithm::Aes128Gcm, None);
        let key = aead.keyring.primary();
        let key_id = key.id();
        let mut nonce = vec![0u8; key.nonce_len()];
        let rng = SystemRng::new();
        rng.fill(&mut nonce);
        let buf = [
            &method.to_be_bytes()[..],
            &key_id.to_be_bytes()[..],
            &nonce[..],
        ]
        .concat();
        let mut dec = Decryptor::new(&aead, buf);
        dec.next(Aad(&[])).unwrap();
        assert_eq!(dec.method, Some(method));
        assert_eq!(dec.key_id, Some(key_id));
        assert!(dec.nonce.is_some());
        let n = dec.nonce.as_ref().unwrap();
        match n {
            Nonce::Single(n) => {
                assert_eq!(n.bytes(), &nonce[..]);
            }
            Nonce::Sequence(_) => {
                panic!("expected nonce, got nonce sequence");
            }
        }
        assert!(dec.backend.is_some());
        assert!(dec.key.is_some());
        assert!(dec.buf.is_empty());
    }
    #[test]
    fn test_parsing_streaming_header() {
        let rng = SystemRng::new();
        let method = Method::StreamingHmacSha256(Segment::FourMegabytes);
        let aead = Aead::new(Algorithm::Aes128Gcm, None);
        let key_id = aead.primary_key().id;
        let mut seed = vec![0u8; aead.primary_key().algorithm.key_len()];
        rng.fill(&mut seed);
        // rand::fill(&mut seed);
        let nonce = vec![0u8; aead.primary_key().algorithm.nonce_prefix_len()];
        rng.fill(&mut seed);
        let buf = [
            &method.to_be_bytes()[..],
            &key_id.to_be_bytes()[..],
            &seed[..],
            &nonce[..],
        ]
        .concat();
        let mut dec = Decryptor::new(aead, buf);

        dec.next(Aad(&[])).unwrap();
        assert_eq!(dec.method, Some(method));
        assert_eq!(dec.key_id, Some(key_id));

        assert!(dec.nonce.is_some());

        let n = dec.nonce.as_ref().unwrap();
        match n {
            Nonce::Single(_) => {
                panic!("expected nonce nonce sequence, got nonce");
            }
            Nonce::Sequence(n) => {
                assert_eq!(
                    n.bytes(),
                    &[&nonce[..], &0u32.to_be_bytes()[..], &[0]].concat()
                );
            }
        }
        assert!(dec.backend.is_some());
        assert!(dec.key.is_some());
        assert!(dec.buf.is_empty());
    }

    #[test]
    fn test_one_shot() {
        let aead = Aead::new(Algorithm::Aes128Gcm, None);
        let mut data = vec![0u8; 1024];
        let rng = SystemRng::new();
        rng.fill(&mut data).unwrap();
        let encryptor = Encryptor::new(&aead, None, data.clone());
        let ciphertext = encryptor.finalize(Aad::empty()).unwrap().next().unwrap();
        let decryptor = Decryptor::new(&aead, ciphertext);
        let result = decryptor.finalize(Aad(&[])).unwrap().next().unwrap();
        assert_eq!(result, data);
    }
    #[test]
    fn test_streaming() {
        let algorithm = Algorithm::Aes128Gcm;
        let aead = Aead::new(Algorithm::Aes128Gcm, None);
        let mut data = vec![0u8; 65536];
        let rng = SystemRng::new();
        rng.fill(&mut data);
        let encryptor = Encryptor::new(&aead, Some(Segment::FourKilobytes), data.clone());
        let enc_seg: Vec<Vec<u8>> = encryptor.finalize(Aad::empty()).unwrap().collect();
        let ciphertext = enc_seg.concat();
        let decryptor = Decryptor::new(&aead, ciphertext);
        let result: Vec<Vec<u8>> = decryptor.finalize(Aad(&[])).unwrap().collect();
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
    #[test]
    fn test_online() {
        let aead = Aead::new(Algorithm::Aes256Gcm, None);

        let enc = Encryptor::new(&aead, None, b"hello world".to_vec());
        // enc.nonce = Some(nonce.clone());
        let ciphertext = enc
            .finalize(Aad(b"additional data"))
            .unwrap()
            .next()
            .unwrap();
        let aad = b"additional data";
        let mut dec = Decryptor::new(&aead, ciphertext);
        assert!(dec.parse_header(aad).unwrap());
        assert_eq!(dec.method, Some(Method::Online));
        assert_eq!(dec.key_id, Some(aead.primary_key().id));
        let result = dec.finalize(Aad(aad)).unwrap().next().unwrap();
        assert_eq!(result, b"hello world");
    }
    #[test]
    fn test_with_aad_roundtrip() {
        let mut data = vec![0u8; 5556];
        let rng = SystemRng::default();
        rng.fill(&mut data);
        let chunks = data.chunks(122).map(Vec::from);
        let algorithm = Algorithm::Aes256Gcm;
        let aead = Aead::new(algorithm, None);
        let key = aead.keyring.primary();
        let mut encryptor = Encryptor::new(&aead, Some(Segment::FourKilobytes), vec![]);
        let mut ciphertext_chunks: Vec<Vec<u8>> = vec![];
        let aad = Aad(b"additional data");

        chunks.for_each(|chunk| {
            encryptor.update(aad, &chunk).unwrap();
            if let Some(result) = encryptor.next() {
                ciphertext_chunks.push(result);
            }
        });

        ciphertext_chunks.extend(encryptor.finalize(aad).unwrap());
        assert_eq!(ciphertext_chunks.len(), 2);
        assert_eq!(ciphertext_chunks[0].len(), 4096);

        let ciphertext = ciphertext_chunks.concat();
        assert_eq!(
            ciphertext[0],
            Method::StreamingHmacSha256(Segment::FourKilobytes)
        );

        let key_id = u32::from_be_bytes(ciphertext[1..5].try_into().unwrap());
        assert_eq!(key_id, key.id());
        assert_eq!(key_id.to_be_bytes(), &key_id.to_be_bytes()[..]);

        let mut cleartext_chunks = vec![];
        let mut decryptor = Decryptor::new(&aead, ciphertext_chunks.concat());
        if let Some(result) = decryptor.next(Aad(aad)).unwrap() {
            cleartext_chunks.push(result);
        }
        for chunk in decryptor.finalize(Aad(aad)).unwrap() {
            cleartext_chunks.push(chunk);
        }

        let mut decryptor = Decryptor::new(&aead, vec![]);
        let mut cleartext_chunks = vec![];

        for chunk in ciphertext_chunks.concat().chunks(40) {
            decryptor.update(Aad(aad), chunk).unwrap();

            if let Some(result) = decryptor.next(Aad(aad)).unwrap() {
                cleartext_chunks.push(result);
            }
        }
        for chunk in decryptor.finalize(Aad(aad)).unwrap() {
            cleartext_chunks.push(chunk);
        }
        let plaintext = cleartext_chunks.concat();
        assert_eq!(plaintext, data);
    }
}
