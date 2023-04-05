#![doc = include_str!("./dsa/README.md")]

mod algorithm;
mod key_info;
mod key_pair;
mod signature;
mod signer;
mod signing_key;
mod verifier;
mod verifying_key;

pub(crate) use verifying_key::VerifyingKey;
pub(crate) type Material = SigningKey;

pub use self::signature::Signature;
pub use algorithm::Algorithm;
pub use key_info::DsaKeyInfo;
use key_pair::KeyPair;

pub use signer::Signer;
use signing_key::SigningKey;
pub use verifier::Verifier;
