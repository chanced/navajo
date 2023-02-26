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
    /// RSA SSA PKCS#1 v1.5 2048 8192 bits SHA-256
    Rs256,
    /// RSA SSA PKCS#1 v1.5 2048 8192 bits SHA-384
    Rs384,
    /// RSA SSA PKCS#1 v1.5 2048 8192 bits SHA-512
    Rs512,
    /// RSA PSS 2048-8192 bits SHA-256
    Ps258,
    /// RSA PSS 2048-8192 bits SHA-384
    Ps384,
    /// RSA PSS 2048-8192 bits SHA-512
    Ps512,
}
impl Algorithm {
    #[cfg(feature = "ring")]
    pub(super) fn ring_ecdsa_signing(&self) -> &'static ring::signature::EcdsaSigningAlgorithm {
        match self {
            Algorithm::Es256 => &ring::signature::ECDSA_P256_SHA256_FIXED_SIGNING,
            Algorithm::Es384 => &ring::signature::ECDSA_P384_SHA384_FIXED_SIGNING,
            _ => panic!("Unsupported algorithm"),
        }
    }
}
