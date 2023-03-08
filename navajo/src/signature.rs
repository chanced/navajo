mod algorithm;
mod material;
mod signature;
mod signer;
mod signing_key;
mod verifier;
mod verifying_key;

pub use algorithm::Algorithm;

pub(crate) use material::Material;

pub use signer::Signer;
pub use verifier::Verifier;

use material::KeyPair;

pub use signature::Signature;



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
