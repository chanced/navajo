use alloc::vec;

use zeroize::ZeroizeOnDrop;

use super::cipher::Cipher;
use super::Algorithm;
use crate::{
    bytes::SensitiveBytes,
    key::{Key, KeyMaterial},
};

#[derive(Clone, ZeroizeOnDrop, Eq)]
pub(super) struct Material {
    bytes: SensitiveBytes,
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
    pub(super) fn create_cipher(&self) -> Cipher {
        Cipher::new(self.algorithm, &self.bytes)
    }
}

impl Key<Material> {
    pub(super) fn bytes(&self) -> &[u8] {
        &self.material_ref().bytes
    }
}
