use core::option::Iter;

use alloc::{collections::VecDeque, vec::Vec};
use ring::error::Unspecified;

use crate::{error::EncryptError, Aead};

use super::{cipher::Cipher, Algorithm, Segment};

pub struct StreamEncryptor {
    key_id: u32,
    algorithm: Algorithm,
    cipher: Option<Cipher>,
    buffer: Vec<u8>,
    ciphertext: VecDeque<u8>,
    nonce: Option<Vec<u8>>,
    segment: Segment,
}

impl StreamEncryptor {
    pub(super) fn new(aead: &Aead, segment: Segment) -> Self {
        let key = aead.keyring.primary_key();
        let algorithm = key.algorithm();
        Self {
            key_id: key.id(),
            algorithm,
            cipher: None,
            buffer: Vec::new(),
            ciphertext: VecDeque::new(),
            nonce: None,
            segment,
        }
    }

    pub(super) fn slice(self, slice: &[u8]) -> Result<Vec<u8>, EncryptError> {
        todo!()
    }
    pub(super) fn update(&mut self, data: &[u8]) {
        // self.cipher.unwrap().
        todo!()
    }

    pub(super) fn finalize(self) -> Result<Vec<u8>, EncryptError> {
        todo!()
    }

    pub(super) fn next(&mut self) -> Option<Vec<u8>> {
        todo!()
    }

    pub(super) fn buffered_len(&self) -> usize {
        self.buffer.len()
    }
}
