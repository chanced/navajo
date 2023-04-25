use std::{fmt::Debug, str::FromStr};

use anyhow::{bail, Context, Result};

use navajo::{secret_store::sync::SecretStore, sensitive};

#[derive(Clone)]
#[repr(transparent)]
pub struct Aad(pub navajo::Aad<sensitive::Bytes>);

impl Debug for Aad {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("Aad")
            .field(&String::from_utf8_lossy(&self.0))
            .finish()
    }
}

impl FromStr for Aad {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        // This is a bit of a hack, but it works for now.
        if s.starts_with("gcp://") || s.starts_with("aws://") || s.starts_with("vault://") {
            let secret = url::Url::parse(s).context("failed to parse envelope secret uri")?;
            let path = secret
                .to_string()
                .replace(&(secret.scheme().to_string() + "://"), "");
            match secret.scheme().to_lowercase().as_str() {
                "gcp" => {
                    let client = navajo_gcp::sync::SecretManager::new();
                    let secret_url = client.get(path)?;
                    Ok(Self(navajo::Aad(secret_url)))
                }
                "aws" => bail!("AWS Secret Manager is not yet implemented"),
                "azure" => bail!("Azure Key Vault is not yet implemented"),
                "vault" => bail!("Vault is not yet implemented"),
                _ => bail!("unknown Secret Store scheme: {}", secret.scheme()),
            }
        } else {
            Ok(Self(navajo::Aad(sensitive::Bytes::from(s.as_bytes()))))
        }
    }
}
