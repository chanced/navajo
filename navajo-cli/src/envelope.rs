use std::{
    io::{Read, Write},
    str::FromStr,
};

use anyhow::{anyhow, bail, Context, Result};
use navajo::{Aad, Aead, Primitive};

use crate::{EncodingReader, EncodingWriter};

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
        let key = shellexpand::full(key).context("failed to expand envelope key")?;
        if !key.contains(':') {
            return Self::open_plaintext(key.to_string());
        }
        let uri = url::Url::parse(&key).context("failed to parse envelope key")?;

        let uri_str = uri
            .to_string()
            .replacen(&(uri.scheme().to_string() + "://"), "", 1);

        match uri.scheme().to_lowercase().as_str() {
            "gcp" => Ok(Envelope::Gcp(navajo_gcp::sync::Kms::new().key(uri_str))),
            "file" | "json" | "plaintext" => Self::open_plaintext(uri_str),
            "aws" => bail!("AWS KMS is not yet implemented"),
            "azure" => bail!("Azure KMS is not yet implemented"),
            "vault" => bail!("Vault KMS is not yet implemented"),
            scheme => bail!("unknown envelope scheme: {}", scheme),
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

    pub fn open<R: Read>(
        &self,
        aad: navajo::Aad<navajo::sensitive::Bytes>,
        mut input: EncodingReader<R>,
    ) -> anyhow::Result<Primitive> {
        let mut data = Vec::new();
        input.read_to_end(&mut data)?;
        match self {
            Envelope::Plaintext(envelope) => Ok(Primitive::open_sync(aad, data, envelope)?),
            Envelope::Gcp(envelope) => Ok(Primitive::open_sync(aad, data, envelope)?),
            Envelope::Json(envelope) => Ok(Primitive::open_sync(aad, data, envelope)?),
        }
    }
    pub fn seal_and_write<A, W: Write>(
        &self,
        mut output: EncodingWriter<W>,
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
        output.write_all(&sealed)?;
        let mut output = output.into_inner()?;
        // output.write_all(b"\n")?; https://github.com/marshallpierce/rust-base64/issues/236
        output.flush()?;

        Ok(())
    }
}
