use std::path::PathBuf;

use crate::{algorithm::Algorithm, envelope::Envelope, secret_store::SecretStore};
use clap::{Parser, Subcommand};
use navajo::{
    primitive::{Kind, Primitive},
    Aead, Daead, Mac, Signer,
};
use tokio::io::{AsyncRead, AsyncWrite};
use url::Url;

#[derive(Debug, Parser)]
#[command(name = "navajo")]
#[command(about = "navajo cli", long_about = None)]
pub struct Cli {
    #[command(subcommand)]
    command: Command,
}

impl Cli {
    pub async fn execute(
        self,
        stdin: impl 'static + AsyncRead,
        stdout: impl 'static + AsyncWrite,
    ) -> Result<(), Box<dyn std::error::Error>> {
        self.command.execute(stdin, stdout).await
    }
}

#[derive(Debug, Subcommand)]
pub enum Command {
    /// Creates a new keyring, optionally encrypting it using a key
    /// from a KMS as an envelope.
    New(New),

    /// Displays information about keys within the keyring.
    #[command(alias = "view")]
    Inpsect(Inspect),

    /// Updates the AAD secret URI and/or change the KMS key URI.
    Migrate(Migrate),

    /// Generates a public JWKS from a private, asymmetric keyring.
    CreatePublic(CreatePublic),

    /// Adds a new key to a keyring.
    AddKey(AddKey),

    /// Promotes a key to primary in a keyring.
    PromoteKey(PromoteKey),

    /// Enables a disabled key in a keyring.
    EnableKey(EnableKey),

    /// Disables a key in a keyring.
    DisableKey(DisableKey),

    /// Deletes a key from a keyring.
    DeleteKey(DeleteKey),

    /// Sets metadata of a key in a keyring.
    SetKeyMetadata(SetKeyMeta),
}

impl Command {
    pub async fn execute(
        self,
        stdin: impl 'static + AsyncRead,
        stdout: impl 'static + AsyncWrite,
    ) -> Result<(), Box<dyn std::error::Error>> {
        match self {
            Command::New(cmd) => cmd.execute(stdin, stdout).await,
            Command::Inpsect(cmd) => cmd.execute(stdin, stdout).await,
            Command::Migrate(cmd) => cmd.execute(stdin, stdout).await,
            Command::CreatePublic(cmd) => cmd.execute(stdin, stdout).await,
            Command::AddKey(cmd) => cmd.execute(stdin, stdout).await,
            Command::PromoteKey(cmd) => cmd.execute(stdin, stdout).await,
            Command::EnableKey(cmd) => cmd.execute(stdin, stdout).await,
            Command::DisableKey(cmd) => cmd.execute(stdin, stdout).await,
            Command::DeleteKey(cmd) => cmd.execute(stdin, stdout).await,
            Command::SetKeyMetadata(cmd) => cmd.execute(stdin, stdout).await,
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
    pub io: IoArgs,
    #[command(flatten)]
    pub envelope: EnvelopeArgs,
    #[arg(value_name = "PUB_ID", long = "public-id", short = 'p')]
    pub pub_id: Option<String>,
}

impl New {
    pub async fn execute(
        self,
        stdin: impl 'static + AsyncRead,
        stdout: impl 'static + AsyncWrite,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let New {
            algorithm,
            envelope: env_args,
            io,
            metadata,
            pub_id,
        } = self;
        let (input, output) = io.get(stdin, stdout).await?;
        let envelope = env_args.get_envelope().await?;
        let secret_store = env_args.get_secret_store().await?;
        let metadata: Option<serde_json::Value> = metadata.into();
        let primitive = match algorithm.kind() {
            Kind::Aead => Primitive::Aead(Aead::new(algorithm.try_into()?, metadata)),
            Kind::Daead => Primitive::Daead(Daead::new(algorithm.try_into()?, metadata)),
            Kind::Mac => Primitive::Mac(Mac::new(algorithm.try_into()?, metadata)),
            Kind::Signature => {
                Primitive::Signature(Signer::new(algorithm.try_into()?, pub_id, metadata))
            }
        };
        let aad = secret_store.map(|(store, path)| {});
        todo!()
    }
}

#[derive(Debug, Parser)]
pub struct Metadata {
    /// Metadata in the form of JSON to associate with the first key, if any.
    ///
    /// If Metadata is not a JSON object or array, it will be treated as a
    /// string.
    pub metadata: Option<String>,
}
impl From<Metadata> for Option<serde_json::Value> {
    fn from(metadata: Metadata) -> Self {
        metadata
            .metadata
            .map(|val| serde_json::from_str(&val).unwrap_or(serde_json::Value::String(val)))
    }
}

#[derive(Debug, Parser)]
pub struct Inspect {
    #[command(flatten)]
    pub io: IoArgs,
    #[command(flatten)]
    pub envelope: EnvelopeArgs,
}

impl Inspect {
    pub async fn execute(
        self,
        stdin: impl 'static + AsyncRead,
        stdout: impl 'static + AsyncWrite,
    ) -> Result<(), Box<dyn std::error::Error>> {
        todo!()
    }
}

#[derive(Debug, Parser)]
pub struct AddKey {
    #[command(flatten)]
    pub io: IoArgs,
    #[command(flatten)]
    pub envelope: EnvelopeArgs,
    /// Specifies the algorithm to use for the key.
    ///     
    /// Errors if the algorithm is not of the same primitive (AEAD, DAEAD,
    /// Signature, MAC) as the keyring.
    pub algorithm: Algorithm,
    /// Metadata in the form of JSON to associate with the key, if any.
    ///
    /// If Metadata is not a JSON object or array, it will be treated as a
    /// string.
    pub metadata: Option<String>,
}

impl AddKey {
    pub async fn execute(
        self,
        stdin: impl 'static + AsyncRead,
        stdout: impl 'static + AsyncWrite,
    ) -> Result<(), Box<dyn std::error::Error>> {
        todo!()
    }
}

#[derive(Debug, Parser)]
pub struct PromoteKey {
    #[command(flatten)]
    op: KeyOpArgs,
}
impl PromoteKey {
    pub async fn execute(
        self,
        stdin: impl 'static + AsyncRead,
        stdout: impl 'static + AsyncWrite,
    ) -> Result<(), Box<dyn std::error::Error>> {
        todo!()
    }
}
#[derive(Debug, Parser)]
pub struct EnableKey {
    #[command(flatten)]
    op: KeyOpArgs,
}
impl EnableKey {
    pub async fn execute(
        self,
        stdin: impl 'static + AsyncRead,
        stdout: impl 'static + AsyncWrite,
    ) -> Result<(), Box<dyn std::error::Error>> {
        todo!()
    }
}
#[derive(Debug, Parser)]
pub struct DisableKey {
    #[command(flatten)]
    op: KeyOpArgs,
}
impl DisableKey {
    pub async fn execute(
        self,
        stdin: impl 'static + AsyncRead,
        stdout: impl 'static + AsyncWrite,
    ) -> Result<(), Box<dyn std::error::Error>> {
        todo!()
    }
}

#[derive(Debug, Parser)]
pub struct DeleteKey {
    #[command(flatten)]
    op: KeyOpArgs,
}
impl DeleteKey {
    pub async fn execute(
        self,
        stdin: impl 'static + AsyncRead,
        stdout: impl 'static + AsyncWrite,
    ) -> Result<(), Box<dyn std::error::Error>> {
        todo!()
    }
}

#[derive(Debug, Parser)]
pub struct Migrate {
    #[command(flatten)]
    io: IoArgs,
    #[command(flatten)]
    envelope: EnvelopeArgs,

    #[arg(value_name = "NEW_ENVELOPE", long = "new-master_key_uri", short = 'n')]
    /// The new URI to a crypto key in a KMS to use as envelope encryption for
    /// the keyring.
    ///
    /// If not specified, the keyring will be re-encrypted with the same key (if any).
    pub new_key_uri: Option<String>,
    /// The new URI to a secret in a cloud secret manager to be used as
    /// additional authenticated data for the keyring.
    #[arg(value_name = "NEW_SECRET_URI", long = "new-secret-uri", short = 'a')]
    pub new_secret_uri: Option<String>,

    /// Disables encryption, outputting the keyring as plaintext JSON.
    #[arg(value_name = "PLAINTEXT", long = "plaintext")]
    pub plaintext: bool,
}

impl Migrate {
    pub async fn execute(
        self,
        stdin: impl 'static + AsyncRead,
        stdout: impl 'static + AsyncWrite,
    ) -> Result<(), Box<dyn std::error::Error>> {
        todo!()
    }
}

#[derive(Debug, Parser)]
pub struct CreatePublic {
    #[command(flatten)]
    pub io: IoArgs,
}

impl CreatePublic {
    pub async fn execute(
        self,
        stdin: impl 'static + AsyncRead,
        stdout: impl 'static + AsyncWrite,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let (input, output) = self.io.get(stdin, stdout).await?;
        todo!()
    }
}

#[derive(Debug, Parser)]
pub struct SetKeyMeta {
    #[command(flatten)]
    pub key_op: KeyOpArgs,
    /// The new metadata for the key. To clear the metadata, use --clear
    ///
    /// Required if --clear is not set
    pub meta: Option<String>,

    /// If set, the metadata for the key will be cleared
    #[arg(value_name = "CLEAR_METADATA", long = "clear")]
    pub clear_metadata: bool,
}
impl SetKeyMeta {
    pub async fn execute(
        self,
        stdin: impl 'static + AsyncRead,
        stdout: impl 'static + AsyncWrite,
    ) -> Result<(), Box<dyn std::error::Error>> {
        todo!()
    }
}

#[derive(Debug, Parser)]
pub struct KeyOpArgs {
    #[command(flatten)]
    pub io: IoArgs,
    #[command(flatten)]
    pub envelope: EnvelopeArgs,

    /// The ID of the key to operate on.
    pub key_id: u32,
}

#[derive(Debug, Parser)]
pub struct IoArgs {
    #[arg(value_name = "INPUT", long = "input", short = 'i')]
    /// The input file to read the keyring from.
    ///
    /// If not specified, stdin is used
    pub input: Option<PathBuf>,

    #[arg(value_name = "OUTPUT", long = "output", short = 'o')]
    /// The output file to write the keyring to.
    ///
    /// If not specified, stdout is used
    pub output: Option<PathBuf>,
}
impl IoArgs {
    pub async fn get(
        self,
        stdin: impl 'static + AsyncRead,
        stdout: impl 'static + AsyncWrite,
    ) -> std::io::Result<(Box<dyn AsyncRead>, Box<dyn AsyncWrite>)> {
        let input: Box<dyn AsyncRead> = if let Some(in_path) = self.input {
            Box::new(tokio::fs::File::open(in_path).await?)
        } else {
            Box::new(stdin)
        };

        let output: Box<dyn AsyncWrite> = if let Some(out_path) = self.output {
            Box::new(tokio::fs::File::create(out_path).await?)
        } else {
            Box::new(stdout)
        };

        Ok((input, output))
    }
}

#[derive(Debug, Parser)]
pub struct EnvelopeArgs {
    #[arg(value_name = "KMS_KEY_URI", long = "kms-key-uri", short = 'k')]
    /// The URI for the crypto key from a KMS to use as envelope encryption if
    /// the keyring is to be encrypted.
    ///
    /// The value should be in the form <gcp|aws|azure|vault>://<key-path>.
    ///
    /// For example, a path of:
    /// gcp://projects/my-project/locations/us-east1/keyRings/my-keyring/cryptoKeys/my-key
    /// would use the key with the ID `my-key` in the keyring `my-keyring` at us-east1 on GCP.
    ///
    pub key_uri: Option<Url>,

    /// The URI for the Secret Store to use for additional authenticated data
    /// (AAD). The URI is of the form <gcp|aws|azure|vault>://<key-path>.
    ///
    /// For example, a path of:
    /// gcp://projects/my-project/secrets/my-secret/versions/1 would use the
    /// first version of the secret "my-secret" on GCP.
    #[arg(value_name = "AAD_SECRET_URI", long = "aad-secret-uri", short = 's')]
    pub aad_secret_store_uri: Option<Url>,
}

impl EnvelopeArgs {
    pub async fn get_envelope(
        &self,
    ) -> Result<(Envelope, Option<String>), Box<dyn std::error::Error>> {
        let uri = self.key_uri.as_ref();
        if uri.is_none() {
            return Ok((Envelope::Cleartext(navajo::CleartextJson), None));
        }
        let uri = uri.unwrap();

        let uri_str = Some(
            uri.to_string()
                .replace(&(uri.scheme().to_string() + "://"), ""),
        );
        match uri.scheme() {
            "gcp" => Ok((Envelope::Gcp(navajo_gcp::Kms::new()), uri_str)),
            "aws" => Err("AWS KMS is not yet implemented".into()),
            "azure" => Err("Azure KMS is not yet implemented".into()),
            "vault" => Err("Vault KMS is not yet implemented".into()),
            _ => Err(format!("unknown KMS scheme: {}", uri.scheme()).into()),
        }
    }
    pub async fn get_secret_store(
        &self,
    ) -> Result<Option<(SecretStore, String)>, Box<dyn std::error::Error>> {
        self.aad_secret_store_uri
            .as_ref()
            .map(|uri| {
                (
                    uri,
                    uri.to_string()
                        .replace(&(uri.scheme().to_string() + "://"), ""),
                )
            })
            .map(|(uri, path)| match uri.scheme() {
                "gcp" => Ok((SecretStore::Gcp(navajo_gcp::SecretManager::new()), path)),
                "aws" => Err("AWS Secret Manager is not yet implemented".into()),
                "azure" => Err("Azure Key Vault is not yet implemented".into()),
                "vault" => Err("Vault is not yet implemented".into()),
                _ => Err(format!("unknown Secret Store scheme: {}", uri.scheme()).into()),
            })
            .transpose()
    }
}
