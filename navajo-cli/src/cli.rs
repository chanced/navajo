use std::{borrow::BorrowMut, path::PathBuf};

use crate::{algorithm::Algorithm, envelope::Envelope};
use anyhow::bail;
use clap::{Parser, Subcommand};
use navajo::{
    secret_store::SecretStore, sensitive, Aad, Aead, Daead, Kind, Mac, Primitive, Signer,
};
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};
use url::Url;

#[derive(Debug, Parser)]
#[command(name = "navajo")]
#[command(about = "navajo cli", long_about = None)]
pub struct Cli {
    #[command(subcommand)]
    command: Command,
}

impl Cli {
    pub async fn run<'a>(
        self,
        stdin: impl 'a + AsyncRead + Unpin,
        stdout: impl 'a + AsyncWrite + Unpin,
    ) -> Result<(), Box<dyn std::error::Error>> {
        self.command.run(stdin, stdout).await
    }
}

#[derive(Debug, Subcommand)]
pub enum Command {
    /// Creates a new keyring, optionally encrypting it using a key
    /// from a KMS as an envelope.
    #[command(alias = "n")]
    New(New),

    /// Displays information about keys within the keyring.
    #[command(
        alias = "view",
        alias = "inspect",
        alias = "show",
        alias = "v",
        alias = "i"
    )]
    Inpsect(Inspect),

    #[command(alias = "m")]
    /// Updates the AAD secret URI and/or change the KMS key URI.
    Migrate(Migrate),

    #[command(alias = "create_public")]
    /// Generates a public JWKS from a private, asymmetric keyring.
    CreatePublic(CreatePublic),

    #[command(alias = "add_key", alias = "add", alias = "a")]
    /// Adds a new key to a keyring.
    AddKey(AddKey),

    #[command(alias = "promote_key", alias = "promote", alias = "p")]
    /// Promotes a key to primary in a keyring.
    PromoteKey(PromoteKey),

    #[command(alias = "enable_key", alias = "enable", alias = "e")]
    /// Enables a disabled key in a keyring.
    EnableKey(EnableKey),

    #[command(alias = "disable_key", alias = "disable", alias = "d")]
    /// Disables a key in a keyring. Disabling a key effectively removes
    /// the key from the keyring, but leaves it in a recoverable state.
    DisableKey(DisableKey),
    /// Deletes a key from a keyring.
    #[command(
        alias = "delete_key",
        alias = "delete",
        alias = "remove",
        alias = "remove-key",
        alias = "remove_key"
    )]
    DeleteKey(DeleteKey),

    /// Sets metadata of a key in a keyring.
    #[command(alias = "set_key_metadata", alias = "metadata")]
    SetKeyMetadata(SetKeyMetadata),
}

impl Command {
    pub async fn run<'a>(
        self,
        stdin: impl 'a + AsyncRead + Unpin,
        stdout: impl 'a + AsyncWrite + Unpin,
    ) -> Result<(), Box<dyn std::error::Error>> {
        match self {
            Command::New(cmd) => cmd.run(stdin, stdout).await,
            Command::Inpsect(cmd) => cmd.run(stdin, stdout).await,
            Command::Migrate(cmd) => cmd.run(stdin, stdout).await,
            Command::CreatePublic(cmd) => cmd.run(stdin, stdout).await,
            Command::AddKey(cmd) => cmd.run(stdin, stdout).await,
            Command::PromoteKey(cmd) => cmd.run(stdin, stdout).await,
            Command::EnableKey(cmd) => cmd.run(stdin, stdout).await,
            Command::DisableKey(cmd) => cmd.run(stdin, stdout).await,
            Command::DeleteKey(cmd) => cmd.run(stdin, stdout).await,
            Command::SetKeyMetadata(cmd) => cmd.run(stdin, stdout).await,
        }
    }
}

#[derive(Debug, Parser)]
pub struct New {
    /// Specifies the algorithm to use for the first key in the keyring.
    pub algorithm: Algorithm,
    #[command(flatten)]
    pub metadata: Metadata,
    #[command(flatten)]
    pub output: Output,
    #[command(flatten)]
    pub integration: IntegrationArgs,
    #[arg(value_name = "PUB_ID", long = "public-id", short = 'p')]
    pub pub_id: Option<String>,
    #[arg(value_name = "PLAINTEXT", long = "plaintext")]
    pub plaintext: bool,
}

impl New {
    pub async fn run<'a>(
        self,
        _stdin: impl 'a + AsyncRead + Unpin,
        stdout: impl 'a + AsyncWrite + Unpin,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let New {
            algorithm,
            integration: env_args,
            output,
            metadata,
            pub_id,
            plaintext,
        } = self;
        if env_args.envelope_key_uri.is_none() && !plaintext {
            return Err("Either --plaintext or --kms-key-uri must be provided".into());
        }

        let output = output.get(stdout).await?;
        let envelope = env_args.get_envelope()?;
        let aad = env_args.get_aad().await?;
        let metadata = metadata.try_into()?;

        let primitive = match algorithm.kind() {
            Kind::Aead => Primitive::Aead(Aead::new(algorithm.try_into()?, metadata)),
            Kind::Daead => Primitive::Daead(Daead::new(algorithm.try_into()?, metadata)),
            Kind::Mac => Primitive::Mac(Mac::new(algorithm.try_into()?, metadata)),
            Kind::Signature => Primitive::Dsa(Signer::new(algorithm.try_into()?, pub_id, metadata)),
        };
        envelope.seal_and_write(output, aad, primitive).await
    }
}

#[derive(Debug, Parser)]
pub struct Metadata {
    /// Metadata for a given key in the form of JSON object.
    pub metadata: Option<String>,
}
impl TryFrom<Metadata> for Option<navajo::Metadata> {
    type Error = serde_json::Error;
    fn try_from(data: Metadata) -> Result<Self, Self::Error> {
        data.metadata.map(|d| serde_json::from_str(&d)).transpose()
    }
}

#[derive(Debug, Parser)]
pub struct Inspect {
    #[command(flatten)]
    pub io: IoArgs,
    #[command(flatten)]
    pub envelope: IntegrationArgs,
}

impl Inspect {
    pub async fn run<'a>(
        self,
        stdin: impl 'a + AsyncRead + Unpin,
        stdout: impl 'a + AsyncWrite + Unpin,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let Inspect { io, envelope } = self;
        let (input, mut output) = io.get(stdin, stdout).await?;
        let aad = envelope.get_aad().await?;
        let envelope = envelope.get_envelope()?;
        let primitive = envelope.open(aad, input).await?;
        let json = match primitive {
            Primitive::Aead(aead) => serde_json::to_vec_pretty(&aead.keys()),
            Primitive::Daead(daead) => serde_json::to_vec_pretty(&daead.keys()),
            Primitive::Mac(mac) => serde_json::to_vec_pretty(&mac.keys()),
            Primitive::Dsa(sig) => serde_json::to_vec_pretty(&sig.keys()),
        }?;

        output.write_all(&json).await?;
        output.write_all(b"\n").await?;
        output.flush().await?;
        Ok(())
    }
}

#[derive(Debug, Parser)]
pub struct AddKey {
    #[command(flatten)]
    pub io: IoArgs,
    #[command(flatten)]
    pub envelope: IntegrationArgs,
    /// Specifies the algorithm to use for the key.
    ///     
    /// Errors if the algorithm is not of the same primitive (AEAD, DAEAD,
    /// Signature, MAC) as the keyring.
    pub algorithm: Algorithm,
    /// Metadata in the form of JSON to associate with the key, if any.
    ///
    /// If Metadata is not a JSON object or array, it will be treated as a
    /// string.
    #[command(flatten)]
    pub metadata: Metadata,
    #[arg(value_name = "PUB_ID", long = "public-id", short = 'p')]
    pub_id: Option<String>,
}

impl AddKey {
    pub async fn run<'a>(
        self,
        stdin: impl 'a + AsyncRead + Unpin,
        stdout: impl 'a + AsyncWrite + Unpin,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let AddKey {
            io,
            envelope,
            algorithm,
            metadata,
            pub_id,
        } = self;
        let (input, output) = io.get(stdin, stdout).await?;
        let aad = envelope.get_aad().await?;
        let envelope = envelope.get_envelope()?;
        let metadata = metadata.try_into()?;
        let mut primitive = envelope.open(aad.clone(), input).await?;
        match primitive {
            Primitive::Aead(ref mut aead) => {
                aead.add(algorithm.try_into()?, metadata);
            }
            Primitive::Daead(ref mut daead) => {
                daead.add(algorithm.try_into()?, metadata);
            }
            Primitive::Mac(ref mut mac) => {
                mac.add(algorithm.try_into()?, metadata);
            }
            Primitive::Dsa(ref mut sig) => {
                sig.add(algorithm.try_into()?, pub_id, metadata)?;
            }
        }
        envelope.seal_and_write(output, aad, primitive).await
    }
}

#[derive(Debug, Parser)]
pub struct PromoteKey {
    #[command(flatten)]
    pub io: IoArgs,
    #[command(flatten)]
    pub envelope: IntegrationArgs,
    /// The ID of the key to operate on.
    pub key_id: u32,
}
impl PromoteKey {
    pub async fn run<'a>(
        self,
        stdin: impl 'a + AsyncRead + Unpin,
        stdout: impl 'a + AsyncWrite + Unpin,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let PromoteKey {
            io,
            envelope,
            key_id,
        } = self;
        let (input, output) = io.get(stdin, stdout).await?;
        let aad = envelope.get_aad().await?;
        let envelope = envelope.get_envelope()?;
        let mut primitive = envelope.open(aad.clone(), input).await?;
        match primitive.borrow_mut() {
            Primitive::Aead(aead) => {
                aead.promote(key_id)?;
            }
            Primitive::Daead(daead) => {
                daead.promote(key_id)?;
            }
            Primitive::Mac(mac) => {
                mac.promote(key_id)?;
            }
            Primitive::Dsa(sig) => {
                sig.promote(key_id)?;
            }
        }
        envelope.seal_and_write(output, aad, primitive).await
    }
}
#[derive(Debug, Parser)]
pub struct EnableKey {
    #[command(flatten)]
    pub io: IoArgs,
    #[command(flatten)]
    pub envelope: IntegrationArgs,
    /// The ID of the key to operate on.
    pub key_id: u32,
}
impl EnableKey {
    pub async fn run<'a>(
        self,
        stdin: impl 'a + AsyncRead + Unpin,
        stdout: impl 'a + AsyncWrite + Unpin,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let EnableKey {
            io,
            envelope,
            key_id,
        } = self;
        let (input, output) = io.get(stdin, stdout).await?;
        let aad = envelope.get_aad().await?;
        let envelope = envelope.get_envelope()?;
        let mut primitive = envelope.open(aad.clone(), input).await?;
        match primitive.borrow_mut() {
            Primitive::Aead(aead) => {
                aead.enable(key_id)?;
            }
            Primitive::Daead(daead) => {
                daead.enable(key_id)?;
            }
            Primitive::Mac(mac) => {
                mac.enable(key_id)?;
            }
            Primitive::Dsa(sig) => {
                sig.enable(key_id)?;
            }
        }
        envelope.seal_and_write(output, aad, primitive).await
    }
}
#[derive(Debug, Parser)]
pub struct DisableKey {
    #[command(flatten)]
    pub io: IoArgs,
    #[command(flatten)]
    pub envelope: IntegrationArgs,
    /// The ID of the key to operate on.
    pub key_id: u32,
}
impl DisableKey {
    pub async fn run<'a>(
        self,
        stdin: impl 'a + AsyncRead + Unpin,
        stdout: impl 'a + AsyncWrite + Unpin,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let DisableKey {
            io,
            envelope,
            key_id,
        } = self;
        let (input, output) = io.get(stdin, stdout).await?;
        let aad = envelope.get_aad().await?;
        let envelope = envelope.get_envelope()?;
        let mut primitive = envelope.open(aad.clone(), input).await?;
        match primitive.borrow_mut() {
            Primitive::Aead(aead) => {
                aead.disable(key_id)?;
            }
            Primitive::Daead(daead) => {
                daead.disable(key_id)?;
            }
            Primitive::Mac(mac) => {
                mac.disable(key_id)?;
            }
            Primitive::Dsa(sig) => {
                sig.disable(key_id)?;
            }
        }
        envelope.seal_and_write(output, aad, primitive).await
    }
}

#[derive(Debug, Parser)]
pub struct DeleteKey {
    #[command(flatten)]
    pub io: IoArgs,
    #[command(flatten)]
    pub envelope: IntegrationArgs,
    /// The ID of the key to operate on.
    pub key_id: u32,
}
impl DeleteKey {
    pub async fn run<'a>(
        self,
        stdin: impl 'a + AsyncRead + Unpin,
        stdout: impl 'a + AsyncWrite + Unpin,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let DeleteKey {
            io,
            envelope,
            key_id,
        } = self;
        let (input, output) = io.get(stdin, stdout).await?;
        let aad = envelope.get_aad().await?;
        let envelope = envelope.get_envelope()?;
        let mut primitive = envelope.open(aad.clone(), input).await?;
        match primitive.borrow_mut() {
            Primitive::Aead(aead) => {
                aead.delete(key_id)?;
            }
            Primitive::Daead(daead) => {
                daead.delete(key_id)?;
            }
            Primitive::Mac(mac) => {
                mac.delete(key_id)?;
            }
            Primitive::Dsa(sig) => {
                sig.delete(key_id)?;
            }
        }
        envelope.seal_and_write(output, aad, primitive).await
    }
}

#[derive(Debug, Parser)]
pub struct Migrate {
    #[command(flatten)]
    io: IoArgs,
    #[command(flatten)]
    envelope: IntegrationArgs,
    #[arg(value_name = "NEW_ENVELOPE", long = "new-master-key-uri", short = 'n')]
    /// The new URI to a crypto key in a KMS to use as envelope encryption for
    /// the keyring.
    ///
    /// If not specified, the keyring will be re-encrypted with the same key (if any).
    pub new_key_uri: Option<Url>,
    /// The new URI to a secret in a cloud secret manager to be used as
    /// additional authenticated data for the keyring.
    #[arg(value_name = "NEW_SECRET_URI", long = "new-secret-uri", short = 'a')]
    pub new_secret_uri: Option<Url>,

    /// Disables encryption, outputting the keyring as plaintext JSON.
    #[arg(value_name = "PLAINTEXT", long = "plaintext")]
    pub plaintext: bool,
}

impl Migrate {
    pub async fn run<'a>(
        self,
        stdin: impl 'a + AsyncRead + Unpin,
        stdout: impl 'a + AsyncWrite + Unpin,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let Migrate {
            envelope,
            io,
            new_key_uri,
            new_secret_uri,
            plaintext,
        } = self;
        let (input, output) = io.get(stdin, stdout).await?;
        let aad = envelope.get_aad().await?;
        let envelope = envelope.get_envelope()?;
        let primitive = envelope.open(aad.clone(), input).await?;

        let updated_args = IntegrationArgs {
            aad_secret_store_uri: new_secret_uri,
            envelope_key_uri: new_key_uri,
        };

        let new_envelope = if updated_args.envelope_key_uri.is_none() && !plaintext {
            envelope
        } else {
            updated_args.get_envelope()?
        };
        let new_aad = if updated_args.aad_secret_store_uri.is_none() && !plaintext {
            aad
        } else {
            updated_args.get_aad().await?
        };
        new_envelope
            .seal_and_write(output, new_aad, primitive)
            .await
    }
}

#[derive(Debug, Parser)]
pub struct CreatePublic {
    #[command(flatten)]
    pub io: IoArgs,
    #[command(flatten)]
    pub envelope: IntegrationArgs,
}

impl CreatePublic {
    pub async fn run<'a>(
        self,
        stdin: impl 'a + AsyncRead + Unpin,
        stdout: impl 'a + AsyncWrite + Unpin,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let CreatePublic { io, envelope } = self;
        let (input, mut output) = io.get(stdin, stdout).await?;
        let aad = envelope.get_aad().await?;
        let envelope = envelope.get_envelope()?;
        let primitive = envelope.open(aad.clone(), input).await?;
        if let Primitive::Dsa(sig) = primitive {
            let public = sig.verifier();
            let jwks = serde_json::to_vec_pretty(&public)?;
            output.write_all(&jwks).await?;
            output.write_all(b"\n").await?;
            output.flush().await?;
        } else {
            return Err("only signature keyrings support public keysets".into());
        }
        Ok(())
    }
}

#[derive(Debug, Parser)]
pub struct SetKeyMetadata {
    #[command(flatten)]
    pub io: IoArgs,
    #[command(flatten)]
    pub envelope: IntegrationArgs,
    /// The ID of the key to operate on.
    pub key_id: u32,
    /// The new metadata for the key. To clear the metadata, use --clear
    ///
    /// Required if --clear is not set
    #[command(flatten)]
    pub metadata: Metadata,

    /// If set, the metadata for the key will be cleared
    #[arg(value_name = "CLEAR_METADATA", long = "clear")]
    pub clear_metadata: bool,
}
impl SetKeyMetadata {
    pub async fn run<'a>(
        self,
        stdin: impl 'a + AsyncRead + Unpin,
        stdout: impl 'a + AsyncWrite + Unpin,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let SetKeyMetadata {
            io,
            envelope,
            key_id,
            metadata,
            clear_metadata,
        } = self;
        let (input, output) = io.get(stdin, stdout).await?;
        let aad = envelope.get_aad().await?;
        let envelope = envelope.get_envelope()?;

        let meta: Option<navajo::Metadata> = if clear_metadata {
            None
        } else {
            metadata.try_into()?
        };

        let mut primitive = envelope.open(aad.clone(), input).await?;
        match primitive.borrow_mut() {
            Primitive::Aead(aead) => {
                aead.set_key_metadata(key_id, meta)?;
            }
            Primitive::Daead(daead) => {
                daead.set_key_metadata(key_id, meta)?;
            }
            Primitive::Mac(mac) => {
                mac.set_key_metadata(key_id, meta)?;
            }
            Primitive::Dsa(sig) => {
                sig.set_key_metadata(key_id, meta)?;
            }
        }
        envelope.seal_and_write(output, aad, primitive).await
    }
}

#[derive(Debug, Clone, Parser)]
pub struct Input {
    /// The input file to read the keyring from.
    ///
    /// If not specified, stdin is used
    #[arg(value_name = "INPUT", long = "input", short = 'i')]
    pub input: Option<PathBuf>,
}
impl Input {
    pub async fn get<'a>(
        self,
        stdin: impl 'a + AsyncRead + Unpin,
    ) -> std::io::Result<Box<dyn 'a + AsyncRead + Unpin>> {
        if let Some(input_path) = self.input {
            Ok(Box::new(tokio::fs::File::open(input_path).await?))
        } else {
            Ok(Box::new(stdin))
        }
    }
}
#[derive(Debug, Clone, Parser)]
pub struct Output {
    /// The output file to write the keyring to.
    ///
    /// If not specified, stdout is used
    #[arg(value_name = "OUTPUT", long = "output", short = 'o')]
    pub output: Option<PathBuf>,
}
impl Output {
    pub async fn get<'a>(
        self,
        stdout: impl 'a + AsyncWrite + Unpin,
    ) -> std::io::Result<Box<dyn 'a + AsyncWrite + Unpin>> {
        if let Some(output_path) = self.output {
            Ok(Box::new(tokio::fs::File::create(output_path).await?))
        } else {
            Ok(Box::new(stdout))
        }
    }
}
#[derive(Debug, Parser)]
pub struct IoArgs {
    #[command(flatten)]
    /// The input file to read the keyring from.
    ///
    /// If not specified, stdin is used
    pub input: Input,

    /// The output file to write the keyring to.
    ///
    /// If not specified, stdout is used
    #[command(flatten)]
    pub output: Output,
}
impl IoArgs {
    pub async fn get<'a>(
        self,
        stdin: impl 'a + AsyncRead + Unpin,
        stdout: impl 'a + AsyncWrite + Unpin,
    ) -> std::io::Result<(Box<dyn AsyncRead + Unpin>, Box<dyn AsyncWrite + Unpin>)> {
        Ok((self.input.get(stdin).await?, self.output.get(stdout).await?))
    }
}

#[derive(Debug, Parser)]
pub struct IntegrationArgs {
    #[arg(
        value_name = "ENVELOPE_URI",
        long = "envelope",
        short = 'e',
        alias = "envelope-uri",
        alias = "envelope-key-uri"
    )]
    /// The URI for the crypto key from a KMS to use as envelope encryption if
    /// the keyring is to be encrypted.
    ///
    /// The value should be in the form <gcp|aws|azure|vault>://<key-path>.
    ///
    ///
    /// - GCP:             gcp://projects/<project-id>/locations/<location>/keyRings/<keyring-id>/cryptoKeys/<key-id>
    ///
    /// - AWS:             aws://arn:aws:kms:<region>:<account-id>:key/<key-id>
    ///
    /// - JSON Plaintext:  json://<path-to-json-file>
    ///
    ///
    pub envelope_key_uri: Option<Url>,

    /// The URI for the Secret Store to use for additional authenticated data
    /// (AAD). The URI is of the form <gcp|aws|azure|vault>://<key-path>.
    ///
    /// For example, a path of:
    /// gcp://projects/my-project/secrets/my-secret/versions/1 would use the
    /// first version of the secret "my-secret" on GCP.
    #[arg(
        value_name = "AAD_SECRET_URI",
        alias = "secret",
        alias = "secret-uri",
        long = "aad-secret-uri",
        short = 's'
    )]
    pub aad_secret_store_uri: Option<Url>,
}

impl IntegrationArgs {
    pub fn get_envelope(&self) -> anyhow::Result<Envelope> {
        todo!()
    }

    pub async fn get_aad(&self) -> anyhow::Result<Aad<sensitive::Bytes>> {
        if let Some(uri) = self.aad_secret_store_uri.as_ref() {
            let path = uri
                .to_string()
                .replace(&(uri.scheme().to_string() + "://"), "");
            match uri.scheme().to_lowercase().as_str() {
                "gcp" => {
                    let client = navajo_gcp::SecretManager::new();
                    let secret = client.get_secret(&path).await?;
                    Ok(Aad(secret))
                }
                "aws" => bail!("AWS Secret Manager is not yet implemented"),
                "azure" => bail!("Azure Key Vault is not yet implemented"),
                "vault" => bail!("Vault is not yet implemented"),
                _ => bail!("unknown Secret Store scheme: {}", uri.scheme()),
            }
        } else {
            Ok(Aad(sensitive::Bytes::default()))
        }
    }
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use strum::IntoEnumIterator;

    use super::*;

    #[tokio::test]
    async fn test_new_plaintext() {
        for alg in Algorithm::iter() {
            let mut w = vec![];

            let new = New {
                algorithm: alg,
                integration: IntegrationArgs {
                    envelope_key_uri: None,
                    aad_secret_store_uri: None,
                },
                metadata: Metadata { metadata: None },
                output: Output { output: None },
                plaintext: true,
                pub_id: None,
            };
            let cli = Cli {
                command: Command::New(new),
            };
            let r_cursor = Cursor::new(r);
            let mut r = vec![];
            let w_cursor = Cursor::new(&mut w);

            cli.run(r_cursor, w_cursor).await.unwrap();
        }
    }

    #[tokio::test]
    async fn test_migrate() {
        // let mut w = vec![];
        // let r = vec![];
        // Cli {
        //     command: Command::Migrate(Migrate {
        //         io: IoArgs {
        //             input: Input { input: None },
        //             output: Output { output: None },
        //         },
        //         envelope: todo!(),
        //         new_key_uri: todo!(),
        //         new_secret_uri: todo!(),
        //         plaintext: todo!(),
        //     }),
        // }
        // .run(r.as_slice(), &mut w)
        // .await
        // .unwrap()
    }
}
