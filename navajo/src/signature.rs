mod algorithm;
mod key_info;
mod key_pair;
mod signature;
mod signer;
mod signing_key;
mod verifier;
mod verifying_key;

pub mod jwt;

pub(crate) use verifying_key::VerifyingKey;
pub(crate) type Material = SigningKey;

pub use algorithm::Algorithm;
pub use key_info::SignatureKeyInfo;
pub use signature::Signature;
pub use signer::Signer;
pub use verifier::Verifier;

use key_pair::KeyPair;
use signing_key::SigningKey;

// #[derive(Clone, Debug, ZeroizeOnDrop)]
// pub struct Signature {
//     keyring: Keyring<Material>,
// }
// impl Signature {
//     pub(crate) fn keyring(&self) -> &Keyring<Material> {
//         &self.keyring
//     }
//     pub(crate) fn from_keyring(keyring: Keyring<Material>) -> Self {
//         Self { keyring }
//     }

//     pub fn new(
//         algorithm: Algorithm,
//         pub_id: Option<String>,
//         meta: Option<serde_json::Value>,
//     ) -> Signature {
//         todo!()
//         // let material = Material::new(algorithm)
//         // let keyring = Keyring::new();
//         // Signature { keyring:  }
//     }
// }
