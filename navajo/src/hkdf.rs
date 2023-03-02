#![doc = include_str!("./hkdf/README.md")]

mod algorithm;
mod prk;
mod salt;

pub use algorithm::Algorithm;
pub use prk::Prk;
pub use salt::Salt;

#[cfg(test)]
mod tests {
    
    use alloc::vec;

    #[test]
    fn test_rust_crypto() {
        let ikm = hex::decode("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b").unwrap();
        let salt = hex::decode("000102030405060708090a0b0c").unwrap();
        let info = hex::decode("f0f1f2f3f4f5f6f7f8f9").unwrap();
        let mut expected = hex::decode(
            "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865",
        )
        .unwrap();

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
            let salt = Salt::new(Algorithm::Sha256, &salt);
            let prk = salt.extract(&ikm);
            let mut okm = [0u8; 42];
            prk.expand(&[&info[..]], &mut okm)
                .expect("42 is a valid length for Sha256 to output");
            assert_eq!(okm[..], expected[..])
        }
        #[cfg(feature = "sha3")]
        {
            use rust_crypto_hkdf::Hkdf;
            use sha3::Sha3_224;
            let hk = Hkdf::<Sha3_224>::new(Some(&salt[..]), &ikm);
            let mut okm = vec![0u8; 42];
            hk.expand(&info, &mut okm).unwrap();
            expected = okm;
            // assert_eq!(okm[..], expected[..]);
        }
        #[cfg(feature = "sha3")]
        {
            use crate::hkdf::*;
            let salt = Salt::new(Algorithm::Sha3_224, &salt[..]);
            let prk = salt.extract(&ikm);
            let mut okm = [0u8; 42];
            prk.expand(&[&info[..]], &mut okm).unwrap();
            assert_eq!(okm[..], expected[..])
        }
    }
}
