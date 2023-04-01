use alloc::vec;

use serde::{Deserialize, Serialize};
use zeroize::ZeroizeOnDrop;

use super::cipher::Cipher;
use super::Algorithm;
use crate::primitive::Kind;
use crate::Rng;
use crate::{
    key::{Key, KeyMaterial},
    sensitive::Bytes,
};

#[derive(Clone, Debug, ZeroizeOnDrop, Eq, Serialize, Deserialize)]
pub(crate) struct Material {
    value: Bytes,
    #[zeroize(skip)]
    #[serde(rename = "alg")]
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
    pub(super) fn generate<G>(rng: &G, algorithm: Algorithm) -> Self
    where
        G: Rng,
    {
        let mut bytes = vec![0u8; algorithm.key_len()];
        rng.fill(&mut bytes).unwrap();
        let bytes = bytes.into();
        Self {
            value: bytes,
            algorithm,
        }
    }
    pub(super) fn cipher(&self) -> Cipher {
        Cipher::new(self.algorithm, &self.value)
    }
    pub(super) fn bytes(&self) -> &[u8] {
        &self.value
    }
}

impl Key<Material> {
    pub(super) fn bytes(&self) -> &[u8] {
        &self.material().value
    }
    pub(super) fn cipher(&self) -> Cipher {
        self.material().cipher()
    }

    pub fn len(&self) -> usize {
        self.bytes().len()
    }
    // pub fn nonce_len(&self) -> usize {
    //     self.algorithm().nonce_len()
    // }
    // pub fn tag_len(&self) -> usize {
    //     self.algorithm().tag_len()
    // }
    // pub fn nonce_prefix_len(&self) -> usize {
    //     self.algorithm().nonce_prefix_len()
    // }
    // pub fn online_header_len(&self) -> usize {
    //     self.algorithm().online_header_len()
    // }
    // pub fn streaming_header_len(&self) -> usize {
    //     self.algorithm().streaming_header_len()
    // }
}
