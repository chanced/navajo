use super::Algorithm;
use crate::{
    daead::cipher::Cipher,
    error::{DecryptDeterministicallyError, EncryptDeterministicallyError},
    key::{Key, KeyMaterial},
    sensitive, Aad, Buffer, Rng,
};
use alloc::{vec, vec::Vec};
use serde::{Deserialize, Serialize};
use zeroize::ZeroizeOnDrop;

#[derive(Clone, ZeroizeOnDrop, Serialize, Debug)]
pub(crate) struct Material {
    #[zeroize(skip)]
    #[serde(rename = "alg")]
    algorithm: Algorithm,
    value: sensitive::Bytes,
}

impl<'de> Deserialize<'de> for Material {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct Data {
            #[serde(rename = "alg")]
            algorithm: Algorithm,
            value: sensitive::Bytes,
        }
        let data = Data::deserialize(deserializer)?;
        if data.value.len() != data.algorithm.key_len() {
            return Err(serde::de::Error::custom("invalid key length"));
        }

        Cipher::new(data.algorithm, &data.value).map_err(serde::de::Error::custom)?;

        Ok(Self {
            algorithm: data.algorithm,
            value: data.value,
        })
    }
}

impl PartialEq for Material {
    fn eq(&self, other: &Self) -> bool {
        self.algorithm == other.algorithm && self.value == other.value
    }
}
impl Eq for Material {}

impl Material {
    pub(super) fn generate<N>(rng: &N, algorithm: Algorithm) -> Self
    where
        N: Rng,
    {
        let mut bytes = vec![0u8; algorithm.key_len()];
        rng.fill(&mut bytes).unwrap();

        Self {
            value: sensitive::Bytes::new(&bytes),
            algorithm,
        }
    }
}

impl Key<Material> {
    pub(super) fn encrypt_deterministically<A>(
        &self,
        aad: Aad<A>,
        plaintext: &[u8],
    ) -> Result<Vec<u8>, EncryptDeterministicallyError>
    where
        A: AsRef<[u8]>,
    {
        let mut buf = plaintext.to_vec();
        self.encrypt_in_place_deterministically(aad, &mut buf)?;
        Ok(buf)
    }

    pub(super) fn encrypt_in_place_deterministically<A, B>(
        &self,
        aad: Aad<A>,
        plaintext: &mut B,
    ) -> Result<(), EncryptDeterministicallyError>
    where
        A: AsRef<[u8]>,
        B: Buffer,
    {
        let mut cipher = self.cipher();
        cipher.encrypt_in_place(aad, plaintext)?;
        plaintext.prepend_slice(&self.key_bytes()[..]);
        Ok(())
    }

    pub(super) fn decrypt_in_place_deterministically<A, B>(
        &self,
        aad: Aad<A>,
        ciphertext: &mut B,
    ) -> Result<(), DecryptDeterministicallyError>
    where
        A: AsRef<[u8]>,
        B: Buffer,
    {
        let mut cipher = self.cipher();
        cipher.decrypt_in_place(aad, ciphertext)?;
        Ok(())
    }

    fn cipher(&self) -> Cipher {
        Cipher::new(self.algorithm(), &self.material().value).unwrap()
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

    // use aes_siv::siv::Aes256Siv;
    // use rust_crypto_aead::KeyInit;

    // use crate::SystemRng;

    // use super::*;

    // #[test]
    // fn spike() {
    //     let mut bytes = vec![0u8; 64];
    //     SystemRng.fill(&mut bytes).unwrap();
    //     let _: sensitive::Bytes = bytes.into();

    //     let k = Aes256Siv::generate_key(rand_core::OsRng::default());
    //     dbg!(k.len());
    // }
}
