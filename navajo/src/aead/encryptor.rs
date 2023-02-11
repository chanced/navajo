use alloc::{collections::VecDeque, vec::Vec};
use ring::error::Unspecified;

use crate::Aead;

use super::{cipher::Cipher, Algorithm, Segment};

pub struct Encryptor {
    key_id: u32,
    algorithm: Algorithm,
    cipher: Option<Cipher>,
    segment_size: Option<Segment>,
    #[cfg(feature = "std")]
    buffer: Vec<u8>,
    #[cfg(not(feature = "std"))]
    buffer: VecDeque<u8>,
    ciphertext: Vec<u8>,
}

impl Encryptor {
    pub fn new(aead: &Aead, segment_size: Option<Segment>) -> Self {
        let key = aead.keyring.primary_key();
        let algorithm = key.algorithm();
        Self {
            key_id: key.id(),
            algorithm,
            cipher: None,
            #[cfg(feature = "std")]
            buffer: Vec::new(),
            #[cfg(not(feature = "std"))]
            buffer: VecDeque::new(),
            segment_size,
            ciphertext: Vec::new(),
        }
    }

    pub fn push(&mut self, data: &[u8]) {
        let mut v: VecDeque<u8> = VecDeque::default();
        v.extend(data.iter());
        cfg_if::cfg_if! {
            if #[cfg(feature = "std")] {{
                    self.buffer.extend_from_slice(data);
            }}
            else {{
                self.buffer.extend(data);
            }}
        }
    }

    pub fn update(&mut self) -> Result<(), Unspecified> {
        todo!()
    }
}
