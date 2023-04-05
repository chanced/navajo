use serde::{Deserialize, Serialize};
use zeroize::ZeroizeOnDrop;

use crate::{
    error::EncryptDeterministicError,
    key::{Key, KeyMaterial},
    sensitive, Aad, Rng,
};

use super::Algorithm;

#[derive(Clone, Debug, ZeroizeOnDrop, Eq, Deserialize, Serialize)]
pub(crate) struct Material {
    #[zeroize(skip)]
    #[serde(rename = "alg")]
    algorithm: Algorithm,
    value: sensitive::Bytes,
}
impl PartialEq for Material {
    fn eq(&self, other: &Self) -> bool {
        self.algorithm == other.algorithm && self.value == other.value
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
}

impl Key<Material> {
    pub(super) fn encrypt<A>(
        &self,
        _aad: Aad<A>,
        _cleartext: &[u8],
    ) -> Result<Vec<u8>, EncryptDeterministicError>
    where
        A: AsRef<[u8]>,
    {
        todo!()
        // safe: there's only one algorithm & the length is controlled
    }
}

impl KeyMaterial for Material {
    type Algorithm = Algorithm;
    fn algorithm(&self) -> Self::Algorithm {
        self.algorithm
    }

    fn kind() -> crate::primitive::Kind {
        crate::primitive::Kind::Daead
    }
}

#[cfg(test)]
mod tests {

    use aes_siv::siv::Aes256Siv;
    use rust_crypto_aead::KeyInit;

    use crate::SystemRng;

    use super::*;

    #[test]
    fn spike() {
        let mut bytes = vec![0u8; 64];
        SystemRng.fill(&mut bytes).unwrap();
        let _: sensitive::Bytes = bytes.into();

        let k = Aes256Siv::generate_key(rand_core::OsRng::default());
        dbg!(k.len());
    }
}
