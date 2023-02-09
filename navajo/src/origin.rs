use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Origin {
    Generated,
    External,
}
impl Default for Origin {
    fn default() -> Self {
        Self::Generated
    }
}
impl Origin {
    pub fn is_navajo(&self) -> bool {
        matches!(self, Self::Generated)
    }
    pub fn is_external(&self) -> bool {
        matches!(self, Self::External)
    }
}
