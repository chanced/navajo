use serde::{Deserialize, Serialize};
use strum::{Display, EnumIter, IntoStaticStr};

#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    Hash,
    Serialize,
    Deserialize,
    IntoStaticStr,
    Display,
    EnumIter,
)]
#[serde(rename_all = "UPPERCASE")]
#[strum(serialize_all = "UPPERCASE")]
pub enum Algorithm {
    /// ECDSA using P-256 and SHA-256
    Es256,
    /// ECDSA using P-384 and SHA-384
    Es384,
    /// Edwards Digital Signature Algorithm (EdDSA) over Curve25519
    #[strum(serialize = "Ed25519")]
    #[serde(rename = "Ed25519")]
    Ed25519,
    // /// RSA SSA PKCS#1 v1.5 2048 8192 bits SHA-256
    // Rs256,
    // /// RSA SSA PKCS#1 v1.5 2048 8192 bits SHA-384
    // Rs384,
    // /// RSA SSA PKCS#1 v1.5 2048 8192 bits SHA-512
    // Rs512,
    // /// RSA PSS 2048-8192 bits SHA-256
    // Ps256,
    // /// RSA PSS 2048-8192 bits SHA-384
    // Ps384,
    // /// RSA PSS 2048-8192 bits SHA-512
    // Ps512,
}
impl Algorithm {
    pub fn jwt_algorithm(&self) -> &'static str {
        match self {
            Algorithm::Es256 => "ES256",
            Algorithm::Es384 => "ES384",
            Algorithm::Ed25519 => "EdDSA",
        }
    }
    pub fn from_jwt_alg(alg: &str) -> Result<Self, &str> {
        match alg.to_uppercase().as_str() {
            "ES256" => Ok(Algorithm::Es256),
            "ES384" => Ok(Algorithm::Es384),
            "EDDSA" => Ok(Algorithm::Ed25519),
            _ => Err("unsupported algorithm: \"{alg}\""),
        }
    }
    pub fn curve(&self) -> Option<&'static str> {
        match self {
            Algorithm::Es256 => Some("P-256"),
            Algorithm::Es384 => Some("P-384"),
            Algorithm::Ed25519 => Some("Ed25519"),
        }
    }
    pub fn key_type(&self) -> &'static str {
        match self {
            Algorithm::Es256 => "EC",
            Algorithm::Es384 => "EC",
            Algorithm::Ed25519 => "OKP",
        }
    }

    #[cfg(feature = "ring")]
    pub(super) fn ring_ecdsa_signing_algorithm(
        &self,
    ) -> &'static ring::signature::EcdsaSigningAlgorithm {
        match self {
            Algorithm::Es256 => &ring::signature::ECDSA_P256_SHA256_FIXED_SIGNING,
            Algorithm::Es384 => &ring::signature::ECDSA_P384_SHA384_FIXED_SIGNING,
            _ => unreachable!("not an ecdsa algorithm: {}", self),
        }
    }
    #[cfg(feature = "ring")]
    pub(super) fn ring_ecdsa_verifying_algorithm(
        &self,
    ) -> &'static ring::signature::EcdsaVerificationAlgorithm {
        match self {
            Algorithm::Es256 => &ring::signature::ECDSA_P256_SHA256_ASN1,
            Algorithm::Es384 => &ring::signature::ECDSA_P384_SHA384_ASN1,
            _ => unreachable!("not an ecdsa algorithm: {}", self),
        }
    }
    // #[cfg(feature = "ring")]
    // pub(super) fn ring_rsa_signing_parameters(&self) -> &'static ring::signature::RsaParameters {
    //     match self {
    // Algorithm::Rs256 => &ring::signature::RSA_PKCS1_2048_8192_SHA256,
    // Algorithm::Rs384 => &ring::signature::RSA_PKCS1_2048_8192_SHA384,
    // Algorithm::Rs512 => &ring::signature::RSA_PKCS1_2048_8192_SHA512,
    // Algorithm::Ps256 => &ring::signature::RSA_PSS_2048_8192_SHA256,
    // Algorithm::Ps384 => &ring::signature::RSA_PSS_2048_8192_SHA384,
    // Algorithm::Ps512 => &ring::signature::RSA_PSS_2048_8192_SHA512,
    //     _ => unreachable!("not an rsa algorithm: {}", self),
    // }
    // }
    #[cfg(feature = "ring")]
    pub(super) fn ring_ed_dsa_parameters(&self) -> &'static ring::signature::EdDSAParameters {
        match self {
            Algorithm::Ed25519 => &ring::signature::ED25519,
            _ => unreachable!("not an eddsa algorithm: {}", self),
        }
    }
}
