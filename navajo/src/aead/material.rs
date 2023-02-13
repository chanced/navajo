use alloc::vec;

use zeroize::ZeroizeOnDrop;

use super::size::{AES_128_GCM, AES_256_GCM, CHACHA20_POLY1305, XCHACHA20_POLY1305};
use super::Algorithm;
use super::{cipher::Cipher, nonce::Nonce};
use crate::{
    key::{Key, KeyMaterial},
    sensitive::Bytes,
    Buffer,
};

#[derive(Clone, ZeroizeOnDrop, Eq)]
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
}

impl Key<Material> {
    pub(super) fn bytes(&self) -> &[u8] {
        &self.material().bytes
    }
    pub(super) fn cipher(&self) -> Cipher {
        self.material().cipher()
    }
    pub fn encrypt_in_place<'a, B: Buffer<'a>>(
        &self,
        data: &'a mut B,
        aad: &[u8],
    ) -> Result<(), crate::error::EncryptError> {
        let nonce = Nonce::new(self.algorithm().nonce_len());

        self.cipher().encrypt_in_place(data, aad, nonce);
        todo!()
    }
}
