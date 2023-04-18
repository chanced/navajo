use std::str::FromStr;

use anyhow::bail;
use clap::ValueEnum;

#[derive(Clone, Copy, PartialEq, Eq, Debug, ValueEnum, strum::Display, strum::EnumIter)]
#[strum(serialize_all = "lowercase")]
/// The encoding of a value
pub enum Encoding {
    /// Base64 encoding which defaults to padding but can decode without padding
    Base64,
    /// Base64 URL encoding which defaults to no padding but can decode with padding
    Base64Url,
    /// Hex encoding
    Hex,
}

impl Encoding {
    pub fn decode<T>(value: T) where T: AsRef<T> {}
}

impl FromStr for Encoding {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match &*s
            .chars()
            .filter(|c| !c.is_whitespace() && *c != '-' && *c != '_')
            .flat_map(|c| c.to_lowercase())
            .collect::<String>()
        {
            "base64" => Ok(Self::Base64),
            "base64url" => Ok(Self::Base64Url),
            _ => bail!("unknown encoding: {}", s),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parsing() {
        println!("{}", Encoding::Base64);
        println!("{}", Encoding::Base64Url);
    }
}
