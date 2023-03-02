use alloc::vec;

use serde::{Deserialize, Serialize};
use zeroize::ZeroizeOnDrop;

use super::backend::Backend;
use super::Algorithm;
use crate::primitive::Kind;
use crate::{
    key::{Key, KeyMaterial},
    sensitive::Bytes,
    Buffer,
};

#[derive(Clone, Debug, ZeroizeOnDrop, Eq, Serialize, Deserialize)]
pub(crate) struct Material {
    value: Bytes,
    #[zeroize(skip)]
    algorithm: Algorithm,
}
impl PartialEq for Material {
    fn eq(&self, other: &Self) -> bool {
        self.algorithm == other.algorithm && self.value == other.value
    }
}
impl KeyMaterial for Material {
    type Algorithm = Algorithm;
    fn algorithm(&self) -> Self::Algorithm {
        self.algorithm
    }

    fn kind() -> Kind {
        Kind::Aead
    }
}
impl Material {
    pub(super) fn new(algorithm: Algorithm) -> Self {
        let bytes = vec![0u8; algorithm.key_len()].into();
        Self {
            value: bytes,
            algorithm,
        }
    }
    pub(super) fn cipher(&self) -> Backend {
        Backend::new(self.algorithm, &self.value)
    }
    pub(super) fn bytes(&self) -> &[u8] {
        &self.value
    }
}

impl Key<Material> {
    pub(super) fn bytes(&self) -> &[u8] {
        &self.material().value
    }
    pub(super) fn cipher(&self) -> Backend {
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
