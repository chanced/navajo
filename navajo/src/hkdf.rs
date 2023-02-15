#![doc = include_str!("./hkdf/README.md")]

mod algorithm;
mod prk;
mod salt;

pub use algorithm::Algorithm;
pub use prk::Prk;
pub use salt::Salt;

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn deleteme() {
        use crate::rand;
        use hex::{decode, encode};
        let mut ikm = [0u8; 32];

        rand::fill(&mut ikm);
        let mut salt = [0u8; 32];
        rand::fill(&mut salt);
        println!("{}\n{}", encode(ikm), encode(salt));
    }

    #[test]
    fn test_rust_crypto() {
        use hex_literal::hex;

        let ikm = hex!("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b");
        let salt = hex!("000102030405060708090a0b0c");
        let info = hex!("f0f1f2f3f4f5f6f7f8f9");
        let mut expected = hex!(
            "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865"
        );

        {
            use rust_crypto_hkdf::Hkdf;
            use sha2::Sha256;
            let hk = Hkdf::<Sha256>::new(Some(&salt[..]), &ikm);
            let mut okm = [0u8; 42];
            hk.expand(&info, &mut okm)
                .expect("42 is a valid length for Sha256 to output");
            assert_eq!(okm[..], expected[..]);
        }

        {
            use crate::hkdf::*;
            let salt = Salt::new(Algorithm::HkdfSha256, &salt[..]);
            let prk = salt.extract(&ikm);
            let mut okm = [0u8; 42];
            prk.expand(&[&info[..]], &mut okm)
                .expect("42 is a valid length for Sha256 to output");
            assert_eq!(okm[..], expected[..])
        }

        {
            use rust_crypto_hkdf::Hkdf;
            use sha3::Sha3_224;
            let hk = Hkdf::<Sha3_224>::new(Some(&salt[..]), &ikm);
            let mut okm = [0u8; 42];
            hk.expand(&info, &mut okm).unwrap();
            expected = okm;
            // assert_eq!(okm[..], expected[..]);
        }

        {
            use crate::hkdf::*;
            let salt = Salt::new(Algorithm::HkdfSha3_224, &salt[..]);
            let prk = salt.extract(&ikm);
            let mut okm = [0u8; 42];
            prk.expand(&[&info[..]], &mut okm).unwrap();
            assert_eq!(okm[..], expected[..])
        }
    }
}
