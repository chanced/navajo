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
#[serde(rename_all = "SCREAMING-KEBAB-CASE")]
#[strum(serialize_all = "SCREAMING-KEBAB-CASE")]
pub enum Algorithm {
    ///AES-SIV is a mode of operation for symmetric key encryption that provides
    ///deterministic authenticated encryption with strong security guarantees,
    ///even in the presence of chosen plaintext attacks and nonce reuse.
    AesSiv,
}
