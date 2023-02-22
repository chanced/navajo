use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, PartialEq, Eq, Clone, Copy, Debug)]
pub enum Algorithm {
    EcdsaP256,
    EcdsaP384,
    Ed25519,
    // RsaSsaPkcs1V15,
    // RsaSsaPss,
}
