use std::{
    io::{Read, Write},
    str::FromStr,
};

use anyhow::{anyhow, bail, Context, Result};
use navajo::{Aad, Aead, Primitive};

use crate::EncodingWriter;

#[derive(Clone, Debug)]
pub enum Envelope {
    /// Plaintext is used when the `--plaintext` argument is provided.
    Plaintext(navajo::PlaintextJson),
    /// Json is a local [`Aead`] keyring stored in plaintext
    ///
    /// `--envelope=json://path/to/file.json`
    Json(Aead),
    Gcp(navajo_gcp::sync::CryptoKey),
}
impl FromStr for Envelope {
    type Err = anyhow::Error;
    fn from_str(key: &str) -> anyhow::Result<Self> {
        let uri = url::Url::parse(key).context("failed to parse envelope key")?;

        let uri_str = uri
            .to_string()
            .replacen(&(uri.scheme().to_string() + "://"), "", 1);

        match uri.scheme().to_lowercase().as_str() {
            "gcp" => Ok(Envelope::Gcp(navajo_gcp::sync::Kms::new().key(uri_str))),
            "plaintext" => Self::open_plaintext(uri_str),
            "aws" => bail!("AWS KMS is not yet implemented"),
            "azure" => bail!("Azure KMS is not yet implemented"),
            "vault" => bail!("Vault KMS is not yet implemented"),
            _ => bail!("unknown KMS scheme: {}", uri.scheme()),
        }
    }
}

impl Envelope {
    pub fn get(envelope: Option<Envelope>, plaintext: bool) -> Result<Envelope> {
        if let Some(envelope) = envelope {
            return Ok(envelope);
        }
        if plaintext {
            return Ok(Envelope::Plaintext(navajo::PlaintextJson));
        }
        bail!("Either --plaintext or --envelope must be provided");
    }

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

    pub fn open<'a>(
        &self,
        aad: navajo::Aad<navajo::sensitive::Bytes>,
        mut read: Box<dyn 'a + Read>,
    ) -> anyhow::Result<Primitive> {
        let mut data = Vec::new();
        read.read_to_end(&mut data)?;
        match self {
            Envelope::Plaintext(envelope) => Ok(Primitive::open_sync(aad, data, envelope)?),
            Envelope::Gcp(envelope) => Ok(Primitive::open_sync(aad, data, envelope)?),
            Envelope::Json(_) => todo!(),
        }
    }
    pub fn seal_and_write<'a, A>(
        &self,
        mut write: EncodingWriter<Box<dyn 'a + Write>>,
        aad: Aad<A>,
        primitive: Primitive,
    ) -> anyhow::Result<()>
    where
        A: 'static + AsRef<[u8]>,
    {
        let sealed = match self {
            Envelope::Plaintext(envelope) => primitive.seal_sync(aad, envelope)?,
            Envelope::Gcp(envelope) => primitive.seal_sync(aad, envelope)?,
            Envelope::Json(envelope) => primitive.seal_sync(aad, envelope)?,
        };
        write.write_all(&sealed)?;
        write.write_all(b"\n")?;
        write.flush()?;
        Ok(())
    }
}
