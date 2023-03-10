#![allow(non_camel_case_types)]

use clap::ValueEnum;

#[derive(Clone, Debug, PartialEq, Eq, ValueEnum)]
pub enum Algorithm {
    // ------------------------------------------
    // AEAD
    // ------------------------------------------
    /// AEAD - AES-128-GCM
    #[clap(
        alias = "AES-128-GCM",
        alias = "AES128GCM",
        alias = "AES_128_GCM",
        alias = "aes-128-gcm",
        alias = "aes_128_gcm"
    )]
    Aes_128_Gcm,
    /// AEAD - AES-256-GCM
    #[clap(
        alias = "AES-256-GCM",
        alias = "AES256GCM",
        alias = "AES_256_GCM",
        alias = "aes-256-gcm",
        alias = "aes_256_gcm"
    )]
    Aes_256_Gcm,
    /// AEAD - ChaCha20-Poly1305
    #[clap(
        alias = "CHACHA20POLY1305",
        alias = "chacha20poly1305",
        alias = "CHACHA20_POLY1305",
        alias = "chacha20_poly1305",
        alias = "ChaCha20-Poly1305",
        alias = "ChaCha20Poly1305",
        alias = "chacha20-poly1305"
    )]
    Chacha20Poly1305,
    /// AEAD - XChaCha20-Poly1305
    #[clap(
        alias = "XCHACHA20POLY1305",
        alias = "xchacha20poly1305",
        alias = "XCHACHA20_POLY1305",
        alias = "xchacha20_poly1305",
        alias = "XChaCha20-Poly1305",
        alias = "XchaCha20-Poly1305",
        alias = "XChaCha20Poly1305",
        alias = "xchacha20-poly1305"
    )]
    Xchacha20Poly1305,

    // ------------------------------------------
    // DAEAD
    // ------------------------------------------
    /// DAEAD - AES-SIV
    #[clap(
        alias = "AES-SIV",
        alias = "AES_SIV",
        alias = "aes-siv",
        alias = "aes_siv"
    )]
    AesSiv,

    // ------------------------------------------
    // MAC
    // ------------------------------------------
    /// MAC - HMAC Blake3
    #[clap(
        alias = "blake3",
        alias = "BLAKE3",
        alias = "Blake3",
        alias = "BLAKE-3",
        alias = "blake-3",
        alias = "BLAKE_3",
        alias = "blake_3"
    )]
    Blake3,
    /// MAC - HMAC Sha256
    #[clap(
        alias = "sha256",
        alias = "sha-256",
        alias = "SHA256",
        alias = "SHA-256",
        alias = "SHA_256",
        alias = "sha_256",
        alias = "SHA2_256",
        alias = "sha2_256",
        alias = "SHA2-256",
        alias = "sha2-256",
        alias = "Sha256",
        alias = "Sha2_256"
    )]
    Sha2_256,
    /// MAC - HMAC Sha384
    #[clap(
        alias = "sha384",
        alias = "sha-384",
        alias = "SHA384",
        alias = "SHA-384",
        alias = "SHA_384",
        alias = "sha_384",
        alias = "SHA2_384",
        alias = "sha2_384",
        alias = "SHA2-384",
        alias = "sha2-384",
        alias = "Sha384",
        alias = "Sha2_384"
    )]
    Sha2_384,
    /// MAC - HMAC Sha512
    #[clap(
        alias = "sha512",
        alias = "sha-512",
        alias = "SHA512",
        alias = "SHA-512",
        alias = "SHA_512",
        alias = "sha_512",
        alias = "SHA2_512",
        alias = "sha2_512",
        alias = "SHA2-512",
        alias = "sha2-512",
        alias = "Sha512",
        alias = "Sha2_512"
    )]
    Sha2_512,
    /// MAC - HMAC Sha3-256
    #[clap(
        alias = "sha3_256",
        alias = "sha3-256",
        alias = "SHA3_256",
        alias = "SHA3-256",
        alias = "Sha3_256",
        alias = "Sha3-256"
    )]
    Sha3_256,
    /// MAC - HMAC Sha3-224
    #[clap(
        alias = "sha3_224",
        alias = "sha3-224",
        alias = "SHA3_224",
        alias = "SHA3-224",
        alias = "Sha3_224",
        alias = "Sha3-224"
    )]
    Sha3_224,
    /// MAC - HMAC Sha3-384
    #[clap(
        alias = "sha3_384",
        alias = "sha3-384",
        alias = "SHA3_384",
        alias = "SHA3-384",
        alias = "Sha3_384",
        alias = "Sha3-384"
    )]
    Sha3_384,
    /// MAC - HMAC Sha3-384
    #[clap(
        alias = "sha3_512",
        alias = "sha3-512",
        alias = "SHA3_512",
        alias = "SHA3-512",
        alias = "Sha3_512",
        alias = "Sha3-512"
    )]
    Sha3_512,
    /// MAC - CMAC AES-128
    #[clap(
        alias = "AES-128",
        alias = "AES128",
        alias = "AES_128",
        alias = "aes-128",
        alias = "aes_128",
        alias = "aes128",
        alias = "cmac-aes-128",
        alias = "cmac_aes_128",
        alias = "cmac_aes-128",
        alias = "cmac-aes128",
        alias = "cmac_aes128"
    )]
    Aes_128,
    /// MAC - CMAC AES-192
    #[clap(
        alias = "AES-192",
        alias = "AES192",
        alias = "AES_192",
        alias = "aes-192",
        alias = "aes_192",
        alias = "aes192",
        alias = "cmac-aes-192",
        alias = "cmac_aes_192",
        alias = "cmac_aes-192",
        alias = "cmac-aes192",
        alias = "cmac_aes192"
    )]
    Aes_192,
    /// MAC - CMAC AES-256
    #[clap(
        alias = "AES-256",
        alias = "AES256",
        alias = "AES_256",
        alias = "aes-256",
        alias = "aes_256",
        alias = "aes256",
        alias = "cmac-aes-256",
        alias = "cmac_aes_256",
        alias = "cmac_aes-256",
        alias = "cmac-aes256",
        alias = "cmac_aes256"
    )]
    Aes_256,

    // ------------------------------------------
    // Signature
    // ------------------------------------------
    /// Signature - ECDSA using P-256 and SHA-256
    Es256,
    /// Signature - ECDSA using P-384 and SHA-384
    Es384,
    /// Signature - Ed25519 Edwards Digital Signature Algorithm (EdDSA) over Curve25519
    Ed25519,
}
