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
impl Origin {
    pub fn is_navajo(&self) -> bool {
        matches!(self, Self::Navajo)
    }
    pub fn is_external(&self) -> bool {
        matches!(self, Self::External)
    }
}
