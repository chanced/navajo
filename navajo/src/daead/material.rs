use serde::{Deserialize, Serialize};
use zeroize::ZeroizeOnDrop;

use crate::{key::KeyMaterial, sensitive};

use super::Algorithm;

#[derive(Clone, Debug, ZeroizeOnDrop, Eq, Serialize, Deserialize)]
pub(crate) struct Material {
    #[zeroize(skip)]
    algorithm: Algorithm,
    bytes: sensitive::Bytes,
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
