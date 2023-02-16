use core::{mem, ops::Range};

use alloc::vec::Vec;
use zeroize::ZeroizeOnDrop;

use crate::{
    buffer::prepend_to_buffer,
    error::{EncryptError, StreamingEncryptFinalizeError, StreamingEncryptNextError},
    hkdf,
    key::Key,
    keyring::KEY_ID_LEN,
    rand, sensitive, Aead,
};

use super::{cipher::Cipher, material::Material, nonce::NonceSequence, Algorithm, Method, Segment};

/// Encrypts data using STREAM as desribed in [Online Authenticated-Encryption
/// and its Nonce-Reuse Misuse-Resistance](https://eprint.iacr.org/2015/189.pdf)
/// if the finalized output is less than the specified `Segment` size.
/// Otherwise, it will encrypt data using AEAD as described in [RFC
/// 5116](https://tools.ietf.org/html/rfc5116) with a 5 byte header prepended.
#[derive(ZeroizeOnDrop)]
pub struct StreamingEncrypt {
    key: Key<Material>,
    buffer: Vec<u8>,
    // ciphertext: Vec<u8>,
    #[zeroize(skip)]
    segment: Segment,
    #[zeroize(skip)]
    nonce_seq: NonceSequence,
    #[zeroize(skip)]
    cipher: Option<Cipher>,
}

impl StreamingEncrypt {
    pub fn new(aead: &Aead, segment: Segment) -> Self {
        let key = aead.keyring.primary_key().clone();
        let algorithm = key.algorithm();
        Self {
            key,
            segment,
            buffer: Vec::with_capacity(segment + algorithm.streaming_header_len() + 1),
            nonce_seq: NonceSequence::new(algorithm.nonce_len()),
            cipher: None,
        }
    }
    fn derive_key(key: &Key<Material>, aad: &[u8]) -> (Vec<u8>, sensitive::Bytes) {
        let mut salt_bytes = vec![0u8; key.algorithm().key_len()];
        rand::fill(&mut salt_bytes);
        let salt = hkdf::Salt::new(hkdf::Algorithm::HkdfSha256, &salt_bytes);
        let prk = salt.extract(&key.material().bytes());
        let mut derived_key = vec![0u8; key.algorithm().key_len()];
        prk.expand(&[aad], &mut derived_key).unwrap(); // safety: key is always an appropriate length
        (salt_bytes, sensitive::Bytes::from(derived_key))
    }
    pub fn update(&mut self, data: &[u8]) {
        self.buffer.extend_from_slice(data);
    }
    pub fn algorithm(&self) -> Algorithm {
        return self.key.algorithm();
    }

    pub fn counter(&self) -> usize {
        self.nonce_seq.counter() as usize
    }

    pub fn buffered_len(&self) -> usize {
        self.buffer.len()
    }

    fn one_shot_header_len(&self) -> usize {
        Method::LEN + KEY_ID_LEN
    }

    fn next_segment_rng(&self) -> Option<Range<usize>> {
        if self.counter() == 0 {
            if self.buffer.len() > self.segment - self.algorithm().header_len() {
                Some(
                    0..self.segment
                        - self.algorithm().streaming_header_len()
                        - self.algorithm().tag_len(),
                )
            } else {
                None
            }
        } else if self.buffer.len() > self.segment - self.algorithm().tag_len() {
            Some(0..self.segment - self.algorithm().tag_len())
        } else {
            None
        }
    }

    fn streaming_header_bytes(&self, salt: &[u8]) -> Vec<u8> {
        let mut header = Vec::with_capacity(self.algorithm().streaming_header_len());
        header.push(Method::StreamingHmacSha256(self.segment).into());
        header.extend_from_slice(&self.key.id().to_be_bytes()[..]);
        header.extend_from_slice(salt);
        header
    }

    fn next_buffered_segment(&mut self) -> Option<Vec<u8>> {
        self.next_segment_rng().map(|rng| {
            let mut buf = self.buffer.split_off(rng.end);
            core::mem::swap(&mut self.buffer, &mut buf);
            buf
        })
    }

    pub fn next(&mut self, aad: &[u8]) -> Result<Option<Vec<u8>>, StreamingEncryptNextError> {
        self.next_buffered_segment()
            .map(|mut buf| {
                let counter = self.counter();
                let nonce = self.nonce_seq.next()?;
                let mut header: Option<Vec<u8>> = None;
                if counter == 0 {
                    let (salt, derived_key) = Self::derive_key(&self.key, aad);
                    let header_bytes = self.streaming_header_bytes(&salt);
                    header = Some(header_bytes);
                    self.cipher = Some(Cipher::new(self.algorithm(), &derived_key))
                }
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
                Ok(buf)
            })
            .transpose()
    }

    /// Finalizes the encryption and returns the remaining segments.
    ///
    /// Finalize **must** be called or the remaining segments will **not** be encrypted.
    #[must_use = "finalize must be called"]
    pub fn finalize(mut self, aad: &[u8]) -> Result<Vec<Vec<u8>>, StreamingEncryptFinalizeError> {
        let mut segments = Vec::new();
        if self.counter() == 0 {
            let buf_len = self.buffered_len();
            let one_shot_len =
                self.one_shot_header_len() + self.algorithm().tag_len() + self.segment;

            if buf_len == 0 {
                return Err(StreamingEncryptFinalizeError::EmptyCleartext);
            } else if buf_len <= one_shot_len {
                return self.finalize_one_shot(aad);
            }
        }
        while let Some(segment) = self.next(aad)? {
            segments.push(segment);
        }
        self.last(aad, segments)
    }

    fn last(
        mut self,
        aad: &[u8],
        mut segments: Vec<Vec<u8>>,
    ) -> Result<Vec<Vec<u8>>, StreamingEncryptFinalizeError> {
        let cipher = self
            .cipher
            .take()
            .ok_or(StreamingEncryptFinalizeError::Unspecified)?;

        if self.buffered_len() == 0 {
            return Ok(segments);
        }
        let nonce = self.nonce_seq.last()?;
        let mut buf = mem::take(&mut self.buffer);

        cipher.encrypt_in_place(nonce, aad, &mut buf)?;
        segments.push(buf);
        Ok(segments)
    }

    fn finalize_one_shot(
        mut self,
        aad: &[u8],
    ) -> Result<Vec<Vec<u8>>, StreamingEncryptFinalizeError> {
        let mut header = Vec::with_capacity(self.one_shot_header_len());
        header.push(Method::Online.into());
        header.extend_from_slice(&self.key.id().to_be_bytes()[..]);
        let cipher = Cipher::new(self.algorithm(), self.key.bytes());

        let nonce = self.nonce_seq.try_into_nonce()?;
        let mut buf = mem::take(&mut self.buffer);

        cipher
            .encrypt_in_place(nonce, aad, &mut buf)
            .map_err(|_| EncryptError::Unspecified)?;

        prepend_to_buffer(&mut self.buffer, &header);
        Ok(vec![buf])
    }
}

#[cfg(test)]
mod tests {}
