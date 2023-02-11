#[cfg(not(feature = "std"))]
use alloc::collections::VecDeque;
use alloc::vec::Vec;
use ring::error::Unspecified;

use crate::Aead;

use super::{cipher::Cipher, Algorithm, Segment};

pub struct Encryptor {
    key_id: u32,
    algorithm: Algorithm,
    cipher: Cipher,
    segment_size: Option<Segment>,
    #[cfg(feature = "std")]
    buffer: Vec<u8>,
    #[cfg(not(feature = "std"))]
    buffer: VecDeque,
    ciphertext: Vec<u8>,
}

impl Encryptor {
    pub fn new(aead: &Aead, segment_size: Option<Segment>) -> Self {
        let key = aead.keyring.primary_key();
        let algorithm = key.algorithm();
        let cipher = Cipher::new(algorithm, key.bytes());
        Self {
            key_id: key.id(),
            algorithm,
            cipher,
            #[cfg(feature = "std")]
            buffer: Vec::new(),
            #[cfg(not(feature = "std"))]
            buffer: VecDeque::new(),
            segment_size,
            ciphertext: Vec::new(),
        }
    }

	pub fn update(&mut self) -> Result<(), Unspecified> {
		let s: ring::aead::SealingKey = ;
	}

}



