use core::str::FromStr;

use crate::strings::to_upper_remove_seperators;

#[derive(Clone, Debug)]
pub enum Zip {
    Deflate,
    Other(String),
}
impl From<&str> for Zip {
    fn from(s: &str) -> Self {
        match to_upper_remove_seperators(s).as_str() {
            "DEF" => Self::Deflate,
            _ => Self::Other(s.to_string()),
        }
    }
}
impl From<String> for Zip {
    fn from(s: String) -> Self {
        Self::from(s.as_str())
    }
}
impl From<&String> for Zip {
    fn from(s: &String) -> Self {
        Self::from(s.as_str())
    }
}
impl FromStr for Zip {
    type Err = ();
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(Self::from(s))
    }
}
