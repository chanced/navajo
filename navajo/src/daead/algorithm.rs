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
    #[strum(serialize = "AES-256-SIV")]
    #[serde(rename = "AES-256-SIV")]
    Aes256Siv,
}

impl Algorithm {
    pub fn key_len(&self) -> usize {
        match self {
            Algorithm::Aes256Siv => 64,
        }
    }
}
