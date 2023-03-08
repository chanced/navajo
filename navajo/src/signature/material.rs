use alloc::string::String;
use serde::{Deserialize, Serialize};
use zeroize::ZeroizeOnDrop;

use crate::{key::KeyMaterial, primitive::Kind, sensitive};

use super::Algorithm;

#[derive(Clone, Debug, ZeroizeOnDrop, Eq, Serialize, Deserialize)]
pub struct Material {
    #[zeroize(skip)]
    algorithm: Algorithm,
    value: KeyPair,
    #[zeroize(skip)]
    pub_id: String,
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
        Kind::Signature
    }
}
impl Material {
    pub(super) fn new(_algorithm: Algorithm, _pub_id: String) -> Self {
        todo!()
    }
}

#[derive(Serialize, Deserialize, Clone, ZeroizeOnDrop, Debug, Eq, PartialEq)]
pub(super) struct KeyPair {
    #[serde(rename = "pvt")]
    pub(super) private: sensitive::Bytes,
    #[serde(rename = "pub")]
    pub(super) public: sensitive::Bytes,
}
impl KeyPair {
    pub(super) fn concat(&self) -> Vec<u8> {
        [self.private.as_ref(), self.public.as_ref()].concat()
    }
}
