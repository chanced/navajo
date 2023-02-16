use core::{mem, ops::Range};

use alloc::vec::Vec;
use zeroize::ZeroizeOnDrop;

use crate::{
    buffer::{prepend_to_buffer, BufferZeroizer},
    error::{
        EncryptError, StreamingEncryptFinalizeError, StreamingEncryptNextError, UnspecifiedError,
    },
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

/// Encrypts data using STREAM as desribed in [Online Authenticated-Encryption
/// and its Nonce-Reuse Misuse-Resistance](https://eprint.iacr.org/2015/189.pdf)
/// if the finalized output is less than the specified `Segment` size.
/// Otherwise, it will encrypt data using AEAD as described in [RFC
/// 5116](https://tools.ietf.org/html/rfc5116) with a 5 byte header prepended.
#[derive(ZeroizeOnDrop, Debug)]
pub struct Encrypt<B>
where
    B: Buffer,
{
    key: Key<Material>,
    buffer: BufferZeroizer<B>,
    #[zeroize(skip)]
    segment: Option<Segment>,
    #[zeroize(skip)]
    nonce_seq: Option<NonceSequence>,
    #[zeroize(skip)] // ring's aead keys do not implement Zeroize. Not sure about Rust Crypto's
    cipher: Option<Cipher>,
}

impl<B> Encrypt<B>
where
    B: Buffer,
{
    pub fn new(buffer: B, segment: Option<Segment>, aead: &Aead) -> Self {
        let key = aead.keyring.primary_key().clone();
        Self {
            key,
            segment,
            buffer: BufferZeroizer(buffer),
            nonce_seq: None,
            cipher: None,
        }
    }

    pub fn update(&mut self, data: &[u8]) {
        self.buffer.extend_from_slice(data)
    }
    pub fn algorithm(&self) -> Algorithm {
        self.key.algorithm()
    }

    pub fn counter(&self) -> usize {
        self.nonce_seq.as_ref().map(|n| n.counter()).unwrap_or(0) as usize
    }

    pub fn buffered_len(&self) -> usize {
        self.buffer.len()
    }

    pub fn next(&mut self, aad: &[u8]) -> Result<Option<B>, StreamingEncryptNextError> {
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

                let cipher = self
                    .cipher
                    .take()
                    .ok_or(StreamingEncryptNextError::Unspecified)?;

                cipher
                    .encrypt_in_place(nonce, aad, &mut buf)
                    .map_err(|_| StreamingEncryptNextError::Unspecified)?;

                if let Some(header) = header {
                    prepend_to_buffer(&mut buf, &header);
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
    pub fn finalize(mut self, aad: &[u8]) -> Result<Vec<B>, StreamingEncryptFinalizeError> {
        let mut segments = Vec::new();
        if self.counter() == 0 {
            let buf_len = self.buffered_len();
            if buf_len == 0 {
                return Err(StreamingEncryptFinalizeError::EmptyCleartext);
            }

            if self.segment.is_none() {
                return self.finalize_one_shot(aad);
            }

            if let Some(segment) = self.segment {
                if buf_len
                    <= self.algorithm().online_header_len() + self.algorithm().tag_len() + segment
                {
                    return self.finalize_one_shot(aad);
                }
            }
        }

        while let Some(seg) = self.next(aad)? {
            segments.push(seg);
        }
        self.last(aad, segments)
    }

    fn finalize_one_shot(mut self, aad: &[u8]) -> Result<Vec<B>, StreamingEncryptFinalizeError> {
        let nonce = Nonce::new(self.algorithm().nonce_len());
        let header = self.header(None, &nonce, &[]);
        let cipher = Cipher::new(self.algorithm(), self.key.bytes());
        let mut buf = mem::take(&mut self.buffer.0);
        cipher
            .encrypt_in_place(nonce, aad, &mut buf)
            .map_err(|_| EncryptError::Unspecified)?;
        prepend_to_buffer(&mut self.buffer, &header);
        Ok(vec![buf])
    }

    fn next_segment_rng(&self) -> Option<Range<usize>> {
        let segment = self.segment?;
        if self.counter() == 0 {
            if self.buffer.len() > segment - self.algorithm().online_header_len() {
                Some(
                    0..segment
                        - self.algorithm().streaming_header_len()
                        - self.algorithm().tag_len(),
                )
            } else {
                None
            }
        } else if self.buffer.len() > segment - self.algorithm().tag_len() {
            Some(0..segment - self.algorithm().tag_len())
        } else {
            None
        }
    }
    fn next_buffered_segment(&mut self) -> Option<BufferZeroizer<B>> {
        self.next_segment_rng().map(|rng| {
            let mut buf = self.buffer.split_off(rng.end);
            core::mem::swap(&mut self.buffer, &mut buf);
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

    fn last(
        mut self,
        aad: &[u8],
        mut segments: Vec<B>,
    ) -> Result<Vec<B>, StreamingEncryptFinalizeError> {
        let cipher = self
            .cipher
            .take()
            .ok_or(StreamingEncryptFinalizeError::Unspecified)?;

        if self.buffered_len() == 0 {
            return Ok(segments);
        }
        let nonce_seq = self.nonce_seq.take().ok_or(UnspecifiedError)?;
        let nonce = nonce_seq.last()?;
        let mut buf = mem::take(&mut self.buffer.0);
        cipher.encrypt_in_place(nonce, aad, &mut buf)?;
        segments.push(buf);
        Ok(segments)
    }
}

#[cfg(test)]
mod tests {}
