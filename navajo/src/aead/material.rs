use zeroize::{Zeroize, ZeroizeOnDrop};

use super::cipher::Cipher;
use super::Algorithm;
use crate::key::{Key, KeyMaterial};

#[derive(Clone, Zeroize, ZeroizeOnDrop, Eq)]
pub(super) struct Material {
    bytes: Vec<u8>,
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
        let bytes = vec![0u8; algorithm.key_len()];
        Self { bytes, algorithm }
    }
    pub(super) fn cipher(&self) -> Cipher {
        Cipher::new(self.algorithm, &self.bytes)
    }
}
impl Key<Material> {}
