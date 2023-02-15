use core::{ops::Range, option::Iter};

use alloc::{collections::VecDeque, vec::Vec};

use crate::{
    error::{EncryptError, SegmentLimitExceeded, StreamingEncryptError},
    keyring::KEY_ID_LEN,
    Aead,
};

use super::{cipher::Cipher, nonce::NonceSequence, Algorithm, Method, Segment};

/// Encrypts data using STREAM as desribed in [Online Authenticated-Encryption
/// and its Nonce-Reuse Misuse-Resistance](https://eprint.iacr.org/2015/189.pdf)
/// if the finalized output is less than the specified `Segment` size.
/// Otherwise, it will encrypt data using AEAD as described in [RFC
/// 5116](https://tools.ietf.org/html/rfc5116) with a 5 byte header prepended.
pub struct StreamingEncrypt {
    key_id: u32,
    algorithm: Algorithm,
    cipher: Option<Cipher>,
    buffer: Vec<u8>,
    // ciphertext: Vec<u8>,
    segment: Segment,
    nonce_seq: NonceSequence,
}

impl StreamingEncrypt {
    pub fn new(aead: &Aead, segment: Segment) -> Self {
        let key = aead.keyring.primary_key();
        let algorithm = key.algorithm();
        Self {
            key_id: key.id(),
            algorithm,
            segment,
            cipher: None,
            buffer: Default::default(),
            // ciphertext: Default::default(),
            nonce_seq: NonceSequence::new(algorithm.nonce_len()),
        }
    }

    pub fn update(&mut self, data: &[u8]) {
        self.buffer.extend_from_slice(data);
    }

    /// Finalizes the encryption and returns the remaining segments.
    ///
    /// Finalize **must** be called or the remaining segments will **not** be encrypted.
    #[must_use = "finalize must be called"]
    pub fn finalize(self) -> Result<Vec<Vec<u8>>, EncryptError> {
        todo!()
    }

    pub fn buffered_len(&self) -> usize {
        self.buffer.len()
    }
    fn counter(&self) -> usize {
        self.nonce_seq.counter() as usize
    }
    fn online_header_len(&self) -> usize {
        Method::LEN + KEY_ID_LEN
    }
    fn streaming_header_len(&self) -> usize {
        self.online_header_len() + self.nonce_seq.prefix_len() + self.algorithm.key_len()
    }
    fn tag_len(&self) -> usize {
        self.algorithm.tag_len()
    }
    fn next_segment_rng(&self) -> Option<(usize, Range<usize>)> {
        let counter = self.counter();
        if counter == 0 {
            if self.buffer.len() > self.segment - self.streaming_header_len() - self.tag_len() {
                Some((
                    counter,
                    0..self.segment - self.streaming_header_len() - self.tag_len(),
                ))
            } else {
                None
            }
        } else if self.buffer.len() <= self.segment {
            None
        } else {
            Some((counter, 0..self.segment.into()))
        }
    }
    fn streaming_header_bytes(&self) -> Vec<u8> {
        let mut header = Vec::with_capacity(self.streaming_header_len());
        header.push(Method::StreamingHmacSha256(self.segment).into());
        header.extend_from_slice(&self.key_id.to_be_bytes());

        header
    }

    fn next_segment(&mut self) -> Option<Vec<u8>> {
        if let Some((counter, next_rng)) = self.next_segment_rng() {
            let mut buf = self.buffer.split_off(next_rng.end);
            core::mem::swap(&mut self.buffer, &mut buf);
            if counter == 0 {
                // let mut header = self.streaming_header_bytes();
                todo!()
            } else {
                Some(Vec::new())
            }
        } else {
            None
        }
    }
}

impl Iterator for StreamingEncrypt {
    type Item = Result<Vec<u8>, SegmentLimitExceeded>;
    fn next(&mut self) -> Option<Self::Item> {
        if self.buffer.len() > self.segment {
            todo!()
        } else if self.buffer.is_empty() {
            None
        } else {
            Some(Err(SegmentLimitExceeded))
        }
    }
}

#[cfg(test)]
mod tests {}
