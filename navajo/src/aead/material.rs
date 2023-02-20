use alloc::vec;

use zeroize::ZeroizeOnDrop;

use super::Algorithm;
use super::{cipher::Cipher, nonce::Nonce};
use crate::{
    key::{Key, KeyMaterial},
    sensitive::Bytes,
    Buffer,
};

#[derive(Clone, Debug, ZeroizeOnDrop, Eq)]
pub(super) struct Material {
    bytes: Bytes,
    #[zeroize(skip)]
    algorithm: Algorithm,
}
impl PartialEq for Material {
    fn eq(&self, other: &Self) -> bool {
        self.algorithm == other.algorithm && self.bytes == other.bytes
    }
}
impl KeyMaterial for Material {
    type Algorithm = Algorithm;
    fn algorithm(&self) -> Self::Algorithm {
        self.algorithm
    }
}
impl Material {
    pub(super) fn new(algorithm: Algorithm) -> Self {
        let bytes = vec![0u8; algorithm.key_len()].into();
        Self { bytes, algorithm }
    }
    pub(super) fn cipher(&self) -> Cipher {
        Cipher::new(self.algorithm, &self.bytes)
    }
    pub(super) fn bytes(&self) -> &[u8] {
        &self.bytes
    }
}

impl Key<Material> {
    pub(super) fn bytes(&self) -> &[u8] {
        &self.material().bytes
    }
    pub(super) fn cipher(&self) -> Cipher {
        self.material().cipher()
    }

    pub fn len(&self) -> usize {
        self.bytes().len()
    }
    pub fn nonce_len(&self) -> usize {
        self.algorithm().nonce_len()
    }
    pub fn tag_len(&self) -> usize {
        self.algorithm().tag_len()
    }
    pub fn nonce_prefix_len(&self) -> usize {
        self.algorithm().nonce_prefix_len()
    }
    pub fn online_header_len(&self) -> usize {
        self.algorithm().online_header_len()
    }
    pub fn streaming_header_len(&self) -> usize {
        self.algorithm().streaming_header_len()
    }
}
