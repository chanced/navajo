#![allow(non_camel_case_types)]

use clap::ValueEnum;

use navajo::primitive::Kind;

#[derive(Clone, Debug, PartialEq, Eq, ValueEnum, strum::Display)]
pub enum Algorithm {
    // ------------------------------------------
    // AEAD
    // ------------------------------------------
    /// AEAD - AES-128-GCM
    #[clap(
        alias = "AES-128-GCM",
        alias = "aes128gcm",
        alias = "AES128GCM",
        alias = "AES_128_GCM",
        alias = "aes-128-gcm",
        alias = "aes_128_gcm"
    )]
    #[strum(serialize = "AES-128-GCM")]
    Aes_128_Gcm,
    /// AEAD - AES-256-GCM
    #[clap(
        alias = "AES-256-GCM",
        alias = "aes256gcm",
        alias = "AES256GCM",
        alias = "AES_256_GCM",
        alias = "aes-256-gcm",
        alias = "aes_256_gcm"
    )]
    #[strum(serialize = "AES-256-GCM")]
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
    #[strum(serialize = "ChaCha20-Poly1305")]
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
    #[strum(serialize = "XChaCha20-Poly1305")]
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
    #[strum(serialize = "AES-SIV")]
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
    #[strum(serialize = "Blake3")]
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
    #[strum(serialize = "SHA-256")]
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
    #[strum(serialize = "SHA-384")]
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
    #[strum(serialize = "SHA-512")]
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
    #[strum(serialize = "SHA3-256")]
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
    #[strum(serialize = "SHA3-224")]
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
    #[strum(serialize = "SHA3-384")]
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
    #[strum(serialize = "SHA3-512")]
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
    #[strum(serialize = "AES-128")]
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
    #[strum(serialize = "AES-192")]
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
    #[strum(serialize = "AES-256")]
    Aes_256,

    // ------------------------------------------
    // Signature
    // ------------------------------------------
    /// Signature - ECDSA using P-256 and SHA-256
    #[clap(
        alias = "ES256",
        alias = "es256",
        alias = "ECDSA_P256_SHA256",
        alias = "ecdsa_p256_sha256"
    )]
    #[strum(serialize = "ES256")]
    Es256,
    /// Signature - ECDSA using P-384 and SHA-384
    #[clap(
        alias = "ES384",
        alias = "es384",
        alias = "ECDSA_P384_SHA384",
        alias = "ecdsa_p384_sha384"
    )]
    #[strum(serialize = "ES384")]
    Es384,
    /// Signature - Ed25519 Edwards Digital Signature Algorithm (EdDSA) over Curve25519
    #[clap(alias = "ED25519", alias = "ed25519")]
    #[strum(serialize = "Ed25519")]
    Ed25519,
}
impl Algorithm {
    pub fn kind(&self) -> Kind {
        match self {
            Algorithm::Aes_128_Gcm
            | Algorithm::Aes_256_Gcm
            | Algorithm::Chacha20Poly1305
            | Algorithm::Xchacha20Poly1305 => Kind::Aead,

            Algorithm::AesSiv => Kind::Daead,

            Algorithm::Blake3
            | Algorithm::Sha2_256
            | Algorithm::Sha2_384
            | Algorithm::Sha2_512
            | Algorithm::Sha3_256
            | Algorithm::Sha3_224
            | Algorithm::Sha3_384
            | Algorithm::Sha3_512
            | Algorithm::Aes_128
            | Algorithm::Aes_192
            | Algorithm::Aes_256 => Kind::Mac,

            Algorithm::Es256 | Algorithm::Es384 | Algorithm::Ed25519 => Kind::Signature,
        }
    }
}
impl TryFrom<Algorithm> for navajo::aead::Algorithm {
    type Error = String;

    fn try_from(value: Algorithm) -> Result<Self, Self::Error> {
        match value {
            Algorithm::Aes_128_Gcm => Ok(navajo::aead::Algorithm::Aes128Gcm),
            Algorithm::Aes_256_Gcm => Ok(navajo::aead::Algorithm::Aes256Gcm),
            Algorithm::Chacha20Poly1305 => Ok(navajo::aead::Algorithm::ChaCha20Poly1305),
            Algorithm::Xchacha20Poly1305 => Ok(navajo::aead::Algorithm::XChaCha20Poly1305),
            _ => Err(format!("Algorithm {value} is not AEAD")),
        }
    }
}
impl TryFrom<Algorithm> for navajo::daead::Algorithm {
    type Error = String;

    fn try_from(value: Algorithm) -> Result<Self, Self::Error> {
        match value {
            Algorithm::AesSiv => Ok(navajo::daead::Algorithm::Aes256Siv),
            _ => Err(format!("Algorithm {value} is not DAEAD")),
        }
    }
}
impl TryFrom<Algorithm> for navajo::dsa::Algorithm {
    type Error = String;

    fn try_from(value: Algorithm) -> Result<Self, Self::Error> {
        match value {
            Algorithm::Es256 => Ok(navajo::dsa::Algorithm::Es256),
            Algorithm::Es384 => Ok(navajo::dsa::Algorithm::Es384),
            Algorithm::Ed25519 => Ok(navajo::dsa::Algorithm::Ed25519),
            _ => Err(format!("Algorithm {value} is not Signature")),
        }
    }
}

impl TryFrom<Algorithm> for navajo::mac::Algorithm {
    type Error = String;
    fn try_from(value: Algorithm) -> Result<Self, Self::Error> {
        match value {
            Algorithm::Blake3 => Ok(navajo::mac::Algorithm::Blake3),
            Algorithm::Sha2_256 => Ok(navajo::mac::Algorithm::Sha256),
            Algorithm::Sha2_384 => Ok(navajo::mac::Algorithm::Sha384),
            Algorithm::Sha2_512 => Ok(navajo::mac::Algorithm::Sha512),
            Algorithm::Sha3_256 => Ok(navajo::mac::Algorithm::Sha3_256),
            Algorithm::Sha3_224 => Ok(navajo::mac::Algorithm::Sha3_224),
            Algorithm::Sha3_384 => Ok(navajo::mac::Algorithm::Sha3_384),
            Algorithm::Sha3_512 => Ok(navajo::mac::Algorithm::Sha3_512),
            Algorithm::Aes_128 => Ok(navajo::mac::Algorithm::Aes128),
            Algorithm::Aes_192 => Ok(navajo::mac::Algorithm::Aes192),
            Algorithm::Aes_256 => Ok(navajo::mac::Algorithm::Aes256),
            _ => Err(format!("Algorithm {value} is not MAC")),
        }
    }
}
