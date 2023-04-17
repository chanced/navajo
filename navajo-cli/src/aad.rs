use std::{ffi::OsStr, str::FromStr};

use anyhow::{bail, Context, Result};

use navajo::secret_store::sync::SecretStore;

#[derive(Clone, PartialEq, Eq, Debug)]
#[repr(transparent)]
pub struct Aad(String);
impl Aad {
    fn get_value(&self) -> Result<String> {
        todo!()
    }

    pub fn value(&self) -> Result<navajo::Aad<navajo::sensitive::Bytes>> {
        // This is a bit of a hack, but it works for now.
        if self.0.starts_with("gcp://")
            || self.0.starts_with("aws://")
            || self.0.starts_with("vault://")
        {
            let secret = url::Url::parse(&self.0).context("failed to parse envelope secret uri")?;
            let path = secret
                .to_string()
                .replace(&(secret.scheme().to_string() + "://"), "");
            match secret.scheme().to_lowercase().as_str() {
                "gcp" => {
                    let client = navajo_gcp::sync::SecretManager::new();
                    let secret_url = client.get(path)?;
                    Ok(navajo::Aad(secret_url))
                }
                "aws" => bail!("AWS Secret Manager is not yet implemented"),
                "azure" => bail!("Azure Key Vault is not yet implemented"),
                "vault" => bail!("Vault is not yet implemented"),
                _ => bail!("unknown Secret Store scheme: {}", secret.scheme()),
            }
        } else {
            todo!()
        }
    }
}

impl From<String> for Aad {
    fn from(s: String) -> Self {
        Self(s)
    }
}

impl From<&String> for Aad {
    fn from(s: &String) -> Self {
        Self(s.to_string())
    }
}

impl TryFrom<&OsStr> for Aad {
    type Error = anyhow::Error;

    fn try_from(s: &OsStr) -> Result<Self, Self::Error> {
        let v = s
            .to_str()
            .ok_or(anyhow::anyhow!("failed to convert {s:?} to utf8"))?
            .to_string();
        Ok(Self(v))
    }
}

impl FromStr for Aad {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(Self(s.to_string()))
    }
}
