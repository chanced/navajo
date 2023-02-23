use serde::{Deserialize, Serialize};
use zeroize::ZeroizeOnDrop;

use crate::{key::KeyMaterial, primitive::Kind, sensitive};

use super::Algorithm;

#[derive(Clone, Debug, ZeroizeOnDrop, Eq, Serialize, Deserialize)]
pub struct Material {
    #[zeroize(skip)]
    algorithm: Algorithm,
    value: sensitive::Bytes,
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
    pub(super) fn new(algorithm: Algorithm) -> Self {
        todo!()
    }
    pub(super) fn bytes(&self) -> &[u8] {
        &self.value
    }
}
