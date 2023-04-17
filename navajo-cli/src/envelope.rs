use std::{io::Read, str::FromStr};

use anyhow::{anyhow, bail, Context};
use navajo::{Aad, Aead, Primitive};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[derive(Clone, Debug)]
pub enum Envelope {
    /// Plaintext is used when the `--plaintext` argument is provided.
    Plaintext(navajo::PlaintextJson),
    /// Json is a local [`Aead`] keyring stored in plaintext
    ///
    /// `--envelope=json://path/to/file.json`
    Json(Aead),
    Gcp(navajo_gcp::CryptoKey),
}
impl FromStr for Envelope {
    type Err = anyhow::Error;
    fn from_str(key: &str) -> Result<Self, Self::Err> {
        let uri = url::Url::parse(key).context("failed to parse envelope key")?;

        let uri_str = uri
            .to_string()
            .replacen(&(uri.scheme().to_string() + "://"), "", 1);

        match uri.scheme().to_lowercase().as_str() {
            "gcp" => Ok(Envelope::Gcp(navajo_gcp::Kms::new().key(uri_str))),
            "plaintext" => Self::open_plaintext(uri_str),
            "aws" => bail!("AWS KMS is not yet implemented"),
            "azure" => bail!("Azure KMS is not yet implemented"),
            "vault" => bail!("Vault KMS is not yet implemented"),
            _ => bail!("unknown KMS scheme: {}", uri.scheme()),
        }
    }
}
impl Envelope {
    pub fn open_plaintext(path: String) -> anyhow::Result<Self> {
        let mut file =
            std::fs::File::open(path).context("failed to open plaintext json envelope file")?;

        let mut data = Vec::new();
        file.read_to_end(&mut data)
            .context("failed to read plaintext json envelope file")?;

        let envelope = Primitive::open_sync(Aad::empty(), data, &navajo::PlaintextJson)
            .context("failed to open plaintext json envelope file")?;

        let envelope = envelope
            .aead()
            .ok_or_else(|| anyhow!("keyring is not AEAD"))
            .context("failed to open plaintext json envelope")?;

        Ok(Envelope::Json(envelope))
    }

    pub async fn open<A>(
        &self,
        aad: Aad<A>,
        mut read: Box<dyn tokio::io::AsyncRead + Unpin>,
    ) -> anyhow::Result<Primitive>
    where
        A: 'static + AsRef<[u8]> + Send + Sync,
    {
        let mut data = Vec::new();
        read.read_to_end(&mut data).await?;
        match self {
            Envelope::Plaintext(envelope) => Ok(Primitive::open(aad, data, envelope).await?),
            Envelope::Gcp(envelope) => Ok(Primitive::open(aad, data, envelope).await?),
            Envelope::Json(_) => todo!(),
        }
    }
    pub async fn seal_and_write<A>(
        &self,
        mut write: Box<dyn tokio::io::AsyncWrite + Unpin>,
        aad: Aad<A>,
        primitive: Primitive,
    ) -> Result<(), Box<dyn std::error::Error>>
    where
        A: 'static + AsRef<[u8]> + Send + Sync,
    {
        let sealed = match self {
            Envelope::Plaintext(envelope) => primitive.seal(aad, envelope).await?,
            Envelope::Gcp(envelope) => primitive.seal(aad, envelope).await?,
            Envelope::Json(envelope) => primitive.seal(aad, envelope).await?,
        };
        write.write_all(&sealed).await?;
        write.write_all(b"\n").await?;
        write.flush().await?;
        Ok(())
    }
}
