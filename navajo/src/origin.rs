use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Origin {
    Navajo,
    External,
}
impl Default for Origin {
    fn default() -> Self {
        Self::Navajo
    }
}
