use core::{mem, ops::Range};

use alloc::collections::{vec_deque::IntoIter, VecDeque};
use alloc::vec;
use alloc::vec::Vec;
use zeroize::ZeroizeOnDrop;

use crate::rand::Rng;
use crate::SystemRng;
use crate::{
    buffer::BufferZeroizer,
    error::{EncryptError, UnspecifiedError},
    hkdf,
    key::Key,
    sensitive, Aad, Aead, Buffer,
};

use super::{
    backend::Backend,
    material::Material,
    nonce::{NonceSequence, SingleNonce},
    Algorithm, Method, Segment,
};
/// Used internally to encrypt data. Exposed as a public type for edge-cases
/// where the [`Aead`] methods [`encrypt_in_place`](`Aead::encrypt_in_place`),
/// [`encrypt`](`Aead::encrypt`), [`encrypt_stream`](`Aead::encrypt_stream`),
/// [`encrypt_try_stream`](`Aead::encrypt_try_stream`) and
/// [`encrypt_writer`](`Aead::encrypt_writer`) are not sufficient.
///
/// Encrypts data using either STREAM as desribed in [Online
/// Authenticated-Encryption and its Nonce-Reuse
/// Misuse-Resistance](https://eprint.iacr.org/2015/189.pdf) if the finalized
/// ciphertext is greater than the specified [`Segment`] as described in [RFC
/// 5116](https://tools.ietf.org/html/rfc5116) with an 5 byte header. Otherwise
/// traditional "online" AEAD encryption is used.
///
/// If the resulting ciphertext is greater than [`Segment`], the header will be
/// in the form:
///
/// ```plaintext
/// || Method (1) || Key Id (4) || Salt (variable) || Nonce Prefix (variable) ||
/// ```
/// where `Salt` is the length of the algorithm's key and `Nonce Prefix` is
/// the length of the algorithm's nonce minus 5 bytes (4 for the segment
/// counter & 1 byte for the last-block flag).
///
/// If the resulting ciphertext is less than [`Segment`], the header will be
/// in the form:
/// ```plaintext
/// || Method (1) || Key Id (4) || Nonce (variable) ||
/// ```
///
/// If the resulting ciphertext is greater than [`Segment`] then each segment block will be
/// be of the size specified by [`Segment`] except for the last, which will be no greater than
/// [`Segment`].
#[derive(ZeroizeOnDrop, Debug)]
pub struct Encryptor<B, N = SystemRng>
where
    B: Buffer,
    N: Rng,
{
    key: Key<Material>,
    buf: BufferZeroizer<B>,
    #[zeroize(skip)]
    segment: Option<Segment>,
    #[zeroize(skip)]
    nonce_seq: Option<NonceSequence>,
    #[zeroize(skip)] // ring's aead keys do not implement Zeroize. Not sure about Rust Crypto's
    cipher: Option<Backend>,
    #[zeroize(skip)]
    segments: VecDeque<B>,

    #[zeroize(skip)]
    rng: N,
}

impl<B, N> Encryptor<B, N>
where
    B: Buffer,
    N: Rng,
{
    pub fn new<C>(rng: N, cipher: C, segment: Option<Segment>, buf: B) -> Self
    where
        N: Rng,
        C: AsRef<Aead>,
    {
        let key = cipher.as_ref().keyring.primary().clone();
        Self {
            key,
            segment,
            buf: BufferZeroizer(buf),
            nonce_seq: None,
            cipher: None,
            segments: VecDeque::new(),
            rng,
        }
    }

    pub fn update<A, C>(&mut self, aad: Aad<A>, plaintext: C) -> Result<(), EncryptError>
    where
        A: AsRef<[u8]>,
        C: AsRef<[u8]>,
    {
        self.buf.extend_from_slice(plaintext.as_ref());
        while let Some(buf) = self.try_encrypt_seg(aad.as_ref())? {
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
                    let nonce_seq =
                        NonceSequence::new(self.rng.clone(), self.algorithm().nonce_len());
                    let (salt, derived_key) = derive_key(self.rng.clone(), &self.key, aad);
                    let header_bytes = self.header(self.segment, nonce_seq.prefix(), &salt);
                    self.nonce_seq = Some(nonce_seq);
                    header = Some(header_bytes);
                    self.cipher = Some(Backend::new(self.algorithm(), &derived_key))
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
    pub fn finalize<A>(mut self, aad: Aad<A>) -> Result<IntoIter<B>, EncryptError>
    where
        A: AsRef<[u8]>,
    {
        if self.counter() == 0 {
            let buf_len = self.buffered_len();
            if buf_len == 0 {
                return Err(EncryptError::EmptyPlaintext);
            }
            if self.segment.is_none() {
                return self.finalize_one_shot(aad.as_ref());
            }
            if let Some(segment) = self.segment {
                if buf_len
                    <= segment - (self.algorithm().online_header_len() + self.algorithm().tag_len())
                {
                    return self.finalize_one_shot(aad.as_ref());
                }
            }
        }
        while let Some(seg) = self.try_encrypt_seg(aad.as_ref())? {
            self.segments.push_back(seg);
        }
        self.last(aad)
    }

    #[allow(clippy::should_implement_trait)]
    pub fn next(&mut self) -> Option<B> {
        self.segments.pop_front()
    }

    fn finalize_one_shot(mut self, aad: &[u8]) -> Result<IntoIter<B>, EncryptError> {
        let nonce = SingleNonce::new(self.rng.clone(), self.algorithm().nonce_len());
        let header = self.header(None, &nonce, &[]);
        let cipher = self.key.cipher();
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

    fn last<A>(mut self, aad: Aad<A>) -> Result<IntoIter<B>, EncryptError>
    where
        A: AsRef<[u8]>,
    {
        let cipher = self.cipher.take().ok_or(EncryptError::Unspecified)?;
        if self.buffered_len() == 0 {
            let segments = mem::take(&mut self.segments);
            return Ok(segments.into_iter());
        }
        let nonce_seq = self.nonce_seq.take().ok_or(UnspecifiedError)?;
        let nonce = nonce_seq.last()?;
        let mut buf = mem::take(&mut self.buf.0);
        cipher.encrypt_in_place(nonce, aad.as_ref(), &mut buf)?;
        self.segments.push_back(buf);
        let segments = mem::take(&mut self.segments);
        Ok(segments.into_iter())
    }
}
fn derive_key<N>(rng: N, key: &Key<Material>, aad: &[u8]) -> (Vec<u8>, sensitive::Bytes)
where
    N: Rng,
{
    let mut salt_bytes = vec![0u8; key.algorithm().key_len()];
    rng.fill(&mut salt_bytes).unwrap();
    let salt = hkdf::Salt::new(hkdf::Algorithm::Sha256, &salt_bytes);
    let prk = salt.extract(key.material().bytes());
    let mut derived_key = vec![0u8; key.algorithm().key_len()];
    prk.expand(&[aad], &mut derived_key).unwrap(); // safety: key is always an appropriate length
    (salt_bytes, sensitive::Bytes::from(derived_key))
}

#[cfg(test)]
mod tests {
    use alloc::vec;
    use alloc::vec::Vec;

    use crate::{
        aead::{segment::FOUR_KB, Algorithm, Method, Segment},
        keyring::KEY_ID_LEN,
        Aad, Aead, SystemRng,
    };

    use super::Encryptor;

    #[test]
    fn test_one_shot_adds_header() {
        let aead = Aead::new(Algorithm::Aes128Gcm, None);
        let key = aead.keyring.primary();
        let rng = SystemRng;
        let mut buf = vec![0u8; 100];
        rng.fill(&mut buf).unwrap();
        let encryptor = Encryptor::new(rng, &aead, None, buf);
        let result = encryptor.finalize(Aad([])).unwrap().next().unwrap();
        assert!(result.len() > 100);
        assert_eq!(result[0], Method::Online);
        assert_eq!(result[1..5], key.id().to_be_bytes()[..]);
    }

    #[test]
    fn test_streaming_buffer_size() {
        let rng = SystemRng;
        let algorithm = Algorithm::Aes128Gcm;
        let aead = Aead::new(algorithm, None);
        let mut buf = vec![0u8; 65536];
        rng.fill(&mut buf).unwrap();
        let encryptor = Encryptor::new(rng, &aead, Some(Segment::FourKilobytes), buf);

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
        let rng = SystemRng;
        let aead = Aead::new(Algorithm::Aes128Gcm, None);
        let key = aead.keyring.primary();
        let mut buf = vec![0u8; 65536];
        rng.fill(&mut buf).unwrap();
        let encryptor = Encryptor::new(rng, &aead, Some(Segment::FourKilobytes), buf);
        let result: Vec<Vec<u8>> = encryptor.finalize(Aad::empty()).unwrap().collect();
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
        let rng = SystemRng;
        let msg = b"hello world.".to_vec();
        let data = b"hello world.".to_vec();

        let enc = Encryptor::new(rng, &aead, None, data);
        let ciphertext = enc
            .finalize(Aad(b"additional data"))
            .unwrap()
            .next()
            .unwrap();

        assert_ne!(ciphertext[Algorithm::Aes256Gcm.online_header_len()..], msg);
        assert_eq!(ciphertext[0], Method::Online);
        assert_eq!(
            ciphertext[1..5],
            aead.keyring.primary().id().to_be_bytes()[..]
        );
    }

    #[test]
    fn test_chunked_segment() {
        let mut data = vec![0u8; 5556];
        let rng = SystemRng::new();
        rng.fill(&mut data).unwrap();
        let chunks = data.chunks(122).map(Vec::from);
        let algorithm = Algorithm::Aes256Gcm;
        let aead = Aead::new(algorithm, None);
        let key = aead.keyring.primary();
        let key_id = key.id();
        let key_material = key.material().bytes();

        let mut encryptor = Encryptor::new(rng, &aead, Some(Segment::FourKilobytes), vec![]);
        let mut ciphertext_chunks: Vec<Vec<u8>> = vec![];
        let aad = b"additional data";

        chunks.for_each(|chunk| {
            encryptor.update(Aad(aad), &chunk).unwrap();
            if let Some(result) = encryptor.next() {
                ciphertext_chunks.push(result);
            }
        });
        assert_eq!(encryptor.counter(), 1);
        let nonce_prefix = encryptor.nonce_seq.as_ref().unwrap().prefix().to_vec();
        ciphertext_chunks.extend(encryptor.finalize(Aad(aad)).unwrap());

        assert_eq!(ciphertext_chunks.len(), 2);
        assert_eq!(ciphertext_chunks[0].len(), 4096);
        assert_eq!(
            ciphertext_chunks[0][0],
            Method::StreamingHmacSha256(Segment::FourKilobytes)
        );
        assert_eq!(ciphertext_chunks[0][1..5], key_id.to_be_bytes()[..]);
        assert_ne!(
            &ciphertext_chunks[0][5..5 + algorithm.key_len()],
            key_material
        );
        assert_eq!(
            &ciphertext_chunks[0]
                [5 + key_material.len()..5 + key_material.len() + nonce_prefix.len()],
            nonce_prefix
        );
    }
}
