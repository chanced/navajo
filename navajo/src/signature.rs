mod algorithm;
mod material;
mod private;
mod public;
mod signer;
mod verifier;

pub use algorithm::Algorithm;
pub(crate) use material::Material;

pub use signer::Signer;
pub use verifier::Verifier;

use zeroize::ZeroizeOnDrop;

use crate::keyring::Keyring;

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
