use core::{mem, ops::Range};

use alloc::{
    collections::{vec_deque::IntoIter, VecDeque},
    vec::Vec,
};
use zeroize::ZeroizeOnDrop;

use crate::{
    buffer::BufferZeroizer,
    error::{EncryptError, UnspecifiedError},
    hkdf,
    key::Key,
    rand, sensitive, Aead, Buffer,
};

use super::{
    cipher::Cipher,
    material::Material,
    nonce::{Nonce, NonceSequence},
    Algorithm, Method, Segment,
};
/// Used internally to encrypt data. Exposed as a public type for edge-cases
/// where the [`Aead`] methods [`encrypt`](`Aead::encrypt`),
/// [`encrypt_stream`](`Aead::encrypt_stream`),
/// [`encrypt_try_stream`](`Aead::encrypt_try_stream`) and
/// [`encrypt_writer`](`Aead::encrypt_writer`) are not sufficient.
///
/// Encrypts data using either STREAM as desribed in [Online
/// Authenticated-Encryption and its Nonce-Reuse
/// Misuse-Resistance](https://eprint.iacr.org/2015/189.pdf) if the finalized
/// output is less than the specified `Segment` size or AEAD as described in
/// [RFC 5116](https://tools.ietf.org/html/rfc5116) with a 5 byte header
/// prepended.
///
#[derive(ZeroizeOnDrop, Debug)]
pub struct Encryptor<B>
where
    B: Buffer,
{
    key: Key<Material>,
    buf: BufferZeroizer<B>,
    #[zeroize(skip)]
    segment: Option<Segment>,
    #[zeroize(skip)]
    nonce_seq: Option<NonceSequence>,
    #[zeroize(skip)] // ring's aead keys do not implement Zeroize. Not sure about Rust Crypto's
    cipher: Option<Cipher>,
    #[zeroize(skip)]
    segments: VecDeque<B>,
    #[zeroize(skip)]
    pub(super) nonce: Option<Nonce>,
}

impl<B> Encryptor<B>
where
    B: Buffer,
{
    pub fn new(aead: &Aead, segment: Option<Segment>, buf: B) -> Self {
        let key = aead.keyring.primary_key().clone();
        Self {
            key,
            segment,
            buf: BufferZeroizer(buf),
            nonce_seq: None,
            cipher: None,
            segments: VecDeque::new(),
            nonce: None,
        }
    }

    pub fn update(&mut self, additional_data: &[u8], data: &[u8]) -> Result<(), EncryptError> {
        self.buf.extend_from_slice(data);
        while let Some(buf) = self.try_encrypt_seg(additional_data)? {
            self.segments.push_back(buf);
        }
        Ok(())
    }

    pub fn algorithm(&self) -> Algorithm {
        self.key.algorithm()
    }

    pub fn counter(&self) -> usize {
        self.nonce_seq.as_ref().map(|n| n.counter()).unwrap_or(0) as usize
    }

    pub fn buffered_len(&self) -> usize {
        self.buf.len()
    }
    fn try_encrypt_seg(&mut self, aad: &[u8]) -> Result<Option<B>, EncryptError> {
        self.next_buffered_segment()
            .map(|mut buf| {
                let mut header: Option<Vec<u8>> = None;
                if self.counter() == 0 {
                    let nonce_seq = NonceSequence::new(self.algorithm().nonce_len());
                    let (salt, derived_key) = Self::derive_key(&self.key, aad);
                    let header_bytes = self.header(self.segment, nonce_seq.prefix(), &salt);
                    self.nonce_seq = Some(nonce_seq);
                    header = Some(header_bytes);
                    self.cipher = Some(Cipher::new(self.algorithm(), &derived_key))
                }
                let nonce = self.nonce_seq.as_mut().ok_or(UnspecifiedError)?.next()?;
                let cipher = self.cipher.take().ok_or(EncryptError::Unspecified)?;
                cipher.encrypt_in_place(nonce, aad, &mut buf)?;
                if let Some(header) = header {
                    buf.prepend_slice(&header);
                }

                self.cipher = Some(cipher);
                let buf = mem::take(&mut buf.0);

                Ok(buf)
            })
            .transpose()
    }

    /// Finalizes the encryption and returns the remaining segments.
    ///
    /// Finalize **must** be called or the remaining segments will **not** be encrypted.
    #[must_use = "finalize must be called"]
    pub fn finalize(mut self, aad: &[u8]) -> Result<IntoIter<B>, EncryptError> {
        if self.counter() == 0 {
            let buf_len = self.buffered_len();
            if buf_len == 0 {
                return Err(EncryptError::EmptyCleartext);
            }
            if self.segment.is_none() {
                return self.finalize_one_shot(aad);
            }
            if let Some(segment) = self.segment {
                if buf_len
                    <= segment - (self.algorithm().online_header_len() + self.algorithm().tag_len())
                {
                    return self.finalize_one_shot(aad);
                }
            }
        }
        while let Some(seg) = self.try_encrypt_seg(aad)? {
            self.segments.push_back(seg);
        }
        self.last(aad)
    }

    #[allow(clippy::should_implement_trait)]
    pub fn next(&mut self) -> Option<B> {
        self.segments.pop_front()
    }

    fn finalize_one_shot(mut self, aad: &[u8]) -> Result<IntoIter<B>, EncryptError> {
        let nonce = self
            .nonce
            .clone()
            .unwrap_or(Nonce::new(self.algorithm().nonce_len()));
        let header = self.header(None, &nonce, &[]);
        let cipher = Cipher::new(self.algorithm(), self.key.bytes());
        let mut buf = mem::take(&mut self.buf.0);
        cipher
            .encrypt_in_place(nonce, aad, &mut buf)
            .map_err(|_| EncryptError::Unspecified)?;
        buf.prepend_slice(&header);
        self.segments.push_front(buf);
        let segments = mem::take(&mut self.segments);
        Ok(segments.into_iter())
    }

    fn next_segment_rng(&self) -> Option<Range<usize>> {
        let segment = self.segment?;
        if self.counter() == 0 {
            if self.buf.len() > segment - self.algorithm().online_header_len() {
                Some(
                    0..segment
                        - self.algorithm().streaming_header_len()
                        - self.algorithm().tag_len(),
                )
            } else {
                None
            }
        } else if self.buf.len() > segment - self.algorithm().tag_len() {
            Some(0..segment - self.algorithm().tag_len())
        } else {
            None
        }
    }
    fn next_buffered_segment(&mut self) -> Option<BufferZeroizer<B>> {
        self.next_segment_rng().map(|rng| {
            let mut buf = self.buf.split_off(rng.end);
            core::mem::swap(&mut self.buf, &mut buf);
            buf
        })
    }
    fn header(&self, segment: Option<Segment>, nonce: &[u8], salt: &[u8]) -> Vec<u8> {
        if let Some(segment) = segment {
            let mut header = Vec::with_capacity(self.algorithm().streaming_header_len());
            header.push(Method::StreamingHmacSha256(segment).into());
            header.extend_from_slice(&self.key.id().to_be_bytes()[..]);
            header.extend_from_slice(salt);
            header.extend_from_slice(nonce);
            header
        } else {
            let mut header = Vec::with_capacity(self.algorithm().online_header_len());
            header.push(Method::Online.into());
            header.extend_from_slice(&self.key.id().to_be_bytes()[..]);
            header.extend_from_slice(nonce);
            header
        }
    }

    fn derive_key(key: &Key<Material>, aad: &[u8]) -> (Vec<u8>, sensitive::Bytes) {
        let mut salt_bytes = vec![0u8; key.algorithm().key_len()];
        rand::fill(&mut salt_bytes);
        let salt = hkdf::Salt::new(hkdf::Algorithm::HkdfSha256, &salt_bytes);
        let prk = salt.extract(key.material().bytes());
        let mut derived_key = vec![0u8; key.algorithm().key_len()];
        prk.expand(&[aad], &mut derived_key).unwrap(); // safety: key is always an appropriate length
        (salt_bytes, sensitive::Bytes::from(derived_key))
    }

    fn last(mut self, aad: &[u8]) -> Result<IntoIter<B>, EncryptError> {
        let cipher = self.cipher.take().ok_or(EncryptError::Unspecified)?;
        if self.buffered_len() == 0 {
            let segments = mem::take(&mut self.segments);
            return Ok(segments.into_iter());
        }
        let nonce_seq = self.nonce_seq.take().ok_or(UnspecifiedError)?;
        let nonce = nonce_seq.last()?;
        let mut buf = mem::take(&mut self.buf.0);
        cipher.encrypt_in_place(nonce, aad, &mut buf)?;
        self.segments.push_back(buf);
        let segments = mem::take(&mut self.segments);
        Ok(segments.into_iter())
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        aead::{nonce::Nonce, segment::FOUR_KB, Algorithm, Method, Segment},
        keyring::KEY_ID_LEN,
        Aead,
    };

    use super::Encryptor;

    #[test]
    fn test_one_shot_adds_header() {
        let aead = Aead::new(Algorithm::Aes128Gcm, None);
        let key = aead.keyring.primary_key();
        let mut buf = vec![0u8; 100];
        crate::rand::fill(&mut buf);
        let encryptor = Encryptor::new(&aead, None, buf);
        let result = encryptor.finalize(&[]).unwrap().next().unwrap();
        assert!(result.len() > 100);
        assert_eq!(result[0], Method::Online);
        assert_eq!(result[1..5], key.id().to_be_bytes()[..]);
    }

    #[test]
    fn test_streaming_buffer_size() {
        let algorithm = Algorithm::Aes128Gcm;
        let aead = Aead::new(algorithm, None);
        let mut buf = vec![0u8; 65536];
        crate::rand::fill(&mut buf);
        let encryptor = Encryptor::new(&aead, Some(Segment::FourKilobytes), buf);

        let expected = FOUR_KB
            - Method::LEN
            - KEY_ID_LEN
            - algorithm.nonce_prefix_len()
            - algorithm.key_len()
            - algorithm.tag_len();
        assert_eq!(Some(0..expected), encryptor.next_segment_rng());
    }

    #[test]
    fn test_streaming_adds_header() {
        let aead = Aead::new(Algorithm::Aes128Gcm, None);
        let key = aead.keyring.primary_key();
        let mut buf = vec![0u8; 65536];
        crate::rand::fill(&mut buf);
        let encryptor = Encryptor::new(&aead, Some(Segment::FourKilobytes), buf);
        let result: Vec<Vec<u8>> = encryptor.finalize(&[]).unwrap().collect();
        assert!(result.len() == 17);
        assert_eq!(
            result[0][0],
            Method::StreamingHmacSha256(Segment::FourKilobytes)
        );
        for (i, r) in result.iter().enumerate() {
            if i < result.len() - 1 {
                assert_eq!(r.len(), 4096);
            } else {
                // assert_eq!(r.len(), 4096 + 16);
            }
        }
        assert_eq!(result[0][1..5], key.id().to_be_bytes()[..]);
        // assert_eq!(result[0], Method::Online);
    }
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

        let mut msg = b"hello world.".to_vec();
        ring_key
            .seal_in_place_append_tag(
                nonce.clone().into(),
                ring::aead::Aad::from(b"additional data"),
                &mut msg,
            )
            .unwrap();
        println!("ring: {msg:?}");

        let data = b"hello world.".to_vec();
        let mut enc = Encryptor::new(&aead, None, data);
        let header = enc.header(None, &nonce, &[]);
        println!("nonce: {:?}", &nonce);
        println!("header: {header:?}");

        enc.nonce = Some(nonce.clone());

        let ciphertext = enc.finalize(b"additional data").unwrap().next().unwrap();
        println!("cipher: {ciphertext:?}");

        assert_eq!(ciphertext[Algorithm::Aes256Gcm.online_header_len()..], msg);
        assert_eq!(ciphertext[0], Method::Online);
        assert_eq!(
            ciphertext[1..5],
            aead.keyring.primary_key().id().to_be_bytes()[..]
        );

        assert_eq!(&ciphertext[5..17], nonce.bytes());
    }
}
