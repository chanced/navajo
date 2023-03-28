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
pub use key_info::SignatureKeyInfo;
use key_pair::KeyPair;

pub use signer::Signer;
use signing_key::SigningKey;
pub use verifier::Verifier;

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
