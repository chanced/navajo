#![doc = include_str!("./dsa/README.md")]

mod algorithm;
mod key_info;
mod key_pair;
mod signature;
mod signer;
mod signing_key;
mod verifier;
mod verifying_key;

pub(crate) use signing_key::SigningKey;
pub(crate) use verifying_key::VerifyingKey;
pub(crate) type Material = SigningKey;

pub use self::signature::Signature;
pub use algorithm::Algorithm;
use key_pair::KeyPair;

pub use key_info::{KeyInfo, KeyringInfo};
pub use signer::Signer;
pub use verifier::Verifier;
