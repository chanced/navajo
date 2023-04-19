use std::{
    borrow::BorrowMut,
    io::{Read, Write},
    path::PathBuf,
};

use crate::{
    algorithm::Algorithm,
    envelope::{self, Envelope},
    Aad, Encoding,
};
use anyhow::{bail, Result};
use clap::{Parser, Subcommand};
use navajo::{sensitive, Aead, Daead, Kind, Mac, Primitive, Signer};
use url::Url;

#[derive(Debug, Parser)]
#[command(name = "navajo")]
#[command(about = "navajo cli", long_about = None)]
pub struct Cli {
    #[command(subcommand)]
    command: Command,
}

impl Cli {
    pub fn run<'a>(self, stdin: impl 'a + Read, stdout: impl 'a + Write) -> Result<()> {
        self.command.run(stdin, stdout)
    }
}
impl From<Command> for Cli {
    fn from(command: Command) -> Self {
        Self { command }
    }
}

#[derive(Debug, Subcommand)]
pub enum Command {
    /// Creates a new keyring, optionally encrypting it using an envelope.
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

    /// Adds a new key to a keyring.
    #[command(alias = "add_key", alias = "add", alias = "a")]
    AddKey(AddKey),

    /// Promotes a key to primary in a keyring.
    #[command(alias = "promote_key", alias = "promote", alias = "p")]
    PromoteKey(PromoteKey),

    /// Enables a disabled key in a keyring.
    #[command(alias = "enable_key", alias = "enable", alias = "e")]
    EnableKey(EnableKey),

    /// Disables a key in a keyring.
    #[command(alias = "disable_key", alias = "disable", alias = "d")]
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

    /// Migrates a keyring to a new envelope, changes the envelope's AAD, or both.
    #[command(alias = "m")]
    Migrate(Migrate),

    /// Generates a public JWKS from a private, asymmetric keyring.
    #[command(alias = "create_public")]
    CreatePublic(CreatePublic),
}

impl Command {
    pub fn run<'a>(self, stdin: impl 'a + Read, stdout: impl 'a + Write) -> Result<()> {
        match self {
            Command::New(cmd) => cmd.run(stdin, stdout),
            Command::Inpsect(cmd) => cmd.run(stdin, stdout),
            Command::Migrate(cmd) => cmd.run(stdin, stdout),
            Command::CreatePublic(cmd) => cmd.run(stdin, stdout),
            Command::AddKey(cmd) => cmd.run(stdin, stdout),
            Command::PromoteKey(cmd) => cmd.run(stdin, stdout),
            Command::EnableKey(cmd) => cmd.run(stdin, stdout),
            Command::DisableKey(cmd) => cmd.run(stdin, stdout),
            Command::DeleteKey(cmd) => cmd.run(stdin, stdout),
            Command::SetKeyMetadata(cmd) => cmd.run(stdin, stdout),
        }
    }
}

impl From<New> for Command {
    fn from(cmd: New) -> Self {
        Command::New(cmd)
    }
}
impl From<Inspect> for Command {
    fn from(cmd: Inspect) -> Self {
        Command::Inpsect(cmd)
    }
}
impl From<Migrate> for Command {
    fn from(cmd: Migrate) -> Self {
        Command::Migrate(cmd)
    }
}
impl From<CreatePublic> for Command {
    fn from(cmd: CreatePublic) -> Self {
        Command::CreatePublic(cmd)
    }
}
impl From<AddKey> for Command {
    fn from(cmd: AddKey) -> Self {
        Command::AddKey(cmd)
    }
}
impl From<PromoteKey> for Command {
    fn from(cmd: PromoteKey) -> Self {
        Command::PromoteKey(cmd)
    }
}
impl From<EnableKey> for Command {
    fn from(cmd: EnableKey) -> Self {
        Command::EnableKey(cmd)
    }
}
impl From<DisableKey> for Command {
    fn from(cmd: DisableKey) -> Self {
        Command::DisableKey(cmd)
    }
}
impl From<DeleteKey> for Command {
    fn from(cmd: DeleteKey) -> Self {
        Command::DeleteKey(cmd)
    }
}
impl From<SetKeyMetadata> for Command {
    fn from(cmd: SetKeyMetadata) -> Self {
        Command::SetKeyMetadata(cmd)
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
    pub env_args: EnvelopeArgs,
    /// For asymetric keys, the public ID of the key to use.
    ///
    /// If not provided, the generated 7-8 digit numeric ID of the key will be
    /// used.
    #[arg(value_name = "PUB_ID", long = "public-id", short = 'p')]
    pub pub_id: Option<String>,

    /// Disables envelope encryption, outputting the keyring as plaintext JSON.
    #[arg(value_name = "PLAINTEXT", long = "plaintext")]
    pub plaintext: bool,
}

impl New {
    pub fn run<'a>(self, _stdin: impl 'a + Read, stdout: impl 'a + Write) -> Result<()> {
        let New {
            algorithm,
            env_args,
            output,
            metadata,
            pub_id,
            plaintext,
        } = self;
        if env_args.envelope.is_none() && !plaintext {
            bail!("Either --plaintext or --envelope must be provided");
        }

        let output = output.get(stdout)?;
        let envelope = env_args.get_envelope(Some(plaintext))?;
        let aad = env_args.get_aad();
        let metadata = metadata.try_into()?;

        let primitive = match algorithm.kind() {
            Kind::Aead => Primitive::Aead(Aead::new(algorithm.try_into()?, metadata)),
            Kind::Daead => Primitive::Daead(Daead::new(algorithm.try_into()?, metadata)),
            Kind::Mac => Primitive::Mac(Mac::new(algorithm.try_into()?, metadata)),
            Kind::Dsa => Primitive::Dsa(Signer::new(algorithm.try_into()?, pub_id, metadata)),
        };
        envelope.seal_and_write(output, aad, primitive)
    }
}

#[derive(Debug, Parser, Default)]
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
    pub envelope_args: EnvelopeArgs,
}

impl Inspect {
    pub fn run<'a>(self, stdin: impl 'a + Read, stdout: impl 'a + Write) -> Result<()> {
        let Inspect { io, envelope_args } = self;
        let (input, mut output) = io.get(stdin, stdout)?;
        let envelope = envelope_args.get_envelope(None)?;
        let aad = envelope_args.get_aad();
        let primitive = envelope.open(aad, input)?;
        let json = match primitive {
            Primitive::Aead(aead) => serde_json::to_vec_pretty(&aead.keys()),
            Primitive::Daead(daead) => serde_json::to_vec_pretty(&daead.keys()),
            Primitive::Mac(mac) => serde_json::to_vec_pretty(&mac.keys()),
            Primitive::Dsa(sig) => serde_json::to_vec_pretty(&sig.keys()),
        }?;

        output.write_all(&json)?;
        output.write_all(b"\n")?;
        output.flush()?;
        Ok(())
    }
}

#[derive(Debug, Parser)]
pub struct AddKey {
    #[command(flatten)]
    pub io: IoArgs,
    #[command(flatten)]
    pub envelope_args: EnvelopeArgs,
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
    pub fn run<'a>(self, stdin: impl 'a + Read, stdout: impl 'a + Write) -> Result<()> {
        let AddKey {
            io,
            envelope_args,
            algorithm,
            metadata,
            pub_id,
        } = self;
        let (input, output) = io.get(stdin, stdout)?;
        let aad = envelope_args.get_aad();
        let envelope = envelope_args.get_envelope(None)?;
        let metadata = metadata.try_into()?;
        let mut primitive = envelope.open(aad.clone(), input)?;
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
        envelope.seal_and_write(output, aad, primitive)
    }
}

#[derive(Debug, Parser)]
pub struct PromoteKey {
    #[command(flatten)]
    pub io: IoArgs,
    #[command(flatten)]
    pub envelope_args: EnvelopeArgs,
    /// The ID of the key to operate on.
    pub key_id: u32,
}
impl PromoteKey {
    pub fn run<'a>(self, stdin: impl 'a + Read, stdout: impl 'a + Write) -> Result<()> {
        let PromoteKey {
            io,
            envelope_args,
            key_id,
        } = self;
        let (input, output) = io.get(stdin, stdout)?;
        let aad = envelope_args.get_aad();
        let envelope = envelope_args.get_envelope(None)?;
        let mut primitive = envelope.open(aad.clone(), input)?;
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
        envelope.seal_and_write(output, aad, primitive)
    }
}
#[derive(Debug, Parser)]
pub struct EnableKey {
    #[command(flatten)]
    pub io: IoArgs,
    #[command(flatten)]
    pub envelope_args: EnvelopeArgs,
    /// The ID of the key to operate on.
    pub key_id: u32,
}
impl EnableKey {
    pub fn run<'a>(self, stdin: impl 'a + Read, stdout: impl 'a + Write) -> Result<()> {
        let EnableKey {
            io,
            envelope_args,
            key_id,
        } = self;
        let (input, output) = io.get(stdin, stdout)?;
        let aad = envelope_args.get_aad();
        let envelope = envelope_args.get_envelope(None)?;
        let mut primitive = envelope.open(aad.clone(), input)?;
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
        envelope.seal_and_write(output, aad, primitive)
    }
}
#[derive(Debug, Parser)]
pub struct DisableKey {
    #[command(flatten)]
    pub io: IoArgs,
    #[command(flatten)]
    pub envelope_args: EnvelopeArgs,
    /// The ID of the key to operate on.
    pub key_id: u32,
}
impl DisableKey {
    pub fn run<'a>(self, stdin: impl 'a + Read, stdout: impl 'a + Write) -> Result<()> {
        let DisableKey {
            io,
            envelope_args,
            key_id,
        } = self;
        let (input, output) = io.get(stdin, stdout)?;
        let aad = envelope_args.get_aad();
        let envelope = envelope_args.get_envelope(None)?;
        let mut primitive = envelope.open(aad.clone(), input)?;
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
        envelope.seal_and_write(output, aad, primitive)
    }
}

#[derive(Debug, Parser)]
pub struct DeleteKey {
    #[command(flatten)]
    pub io: IoArgs,
    #[command(flatten)]
    pub envelope_args: EnvelopeArgs,
    /// The ID of the key to operate on.
    pub key_id: u32,
}
impl DeleteKey {
    pub fn run<'a>(self, stdin: impl 'a + Read, stdout: impl 'a + Write) -> Result<()> {
        let DeleteKey {
            io,
            envelope_args,
            key_id,
        } = self;
        let (input, output) = io.get(stdin, stdout)?;
        let aad = envelope_args.get_aad();
        let envelope = envelope_args.get_envelope(None)?;
        let mut primitive = envelope.open(aad.clone(), input)?;
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
        envelope.seal_and_write(output, aad, primitive)
    }
}

#[derive(Debug, Parser)]
pub struct Migrate {
    #[command(flatten)]
    io: IoArgs,

    #[command(flatten)]
    envelope_args: EnvelopeArgs,

    /// The new URI to a crypto key in a KMS to use as envelope encryption for
    /// the keyring.
    ///
    /// If not specified, the keyring will be re-encrypted with the same key (if any).
    #[arg(value_name = "NEW_ENVELOPE", long = "new-envelope")]
    pub new_envelope: Option<Envelope>,

    /// The new URI to a secret in a cloud secret manager to be used as
    /// additional authenticated data for the keyring.
    #[arg(value_name = "NEW_ENVELOPE_AAD", long = "new-envelope-aad")]
    pub new_envelope_aad: Option<Aad>,

    #[arg(
        value_name = "NEW_ENVELOPE_AAD_ENCODING",
        long = "new-envelope-aad-encoding"
    )]
    pub new_envelope_aad_encoding: Option<Encoding>,

    /// If set, the keyring will have encryption disabled and will be output to plaintext JSON.
    #[arg(value_name = "PLAINTEXT", long = "plaintext")]
    pub plaintext: bool,
}

impl Migrate {
    pub fn run<'a>(self, stdin: impl 'a + Read, stdout: impl 'a + Write) -> Result<()> {
        let Migrate {
            envelope_args,
            io,
            new_envelope: new_key_uri,
            new_envelope_aad,
            plaintext,
            new_envelope_aad_encoding,
        } = self;
        let (input, output) = io.get(stdin, stdout)?;
        let aad = envelope_args.get_aad();
        let current_envelope = envelope_args.get_envelope(None)?;
        let primitive = current_envelope.open(aad.clone(), input)?;

        let updated_args = EnvelopeArgs {
            envelope_aad: new_envelope_aad,
            envelope: new_key_uri,
            envelope_aad_encoding: new_envelope_aad_encoding,
        };

        let new_envelope = if updated_args.envelope.is_none() && !plaintext {
            current_envelope
        } else {
            updated_args.get_envelope(Some(plaintext))?
        };
        let new_aad = if updated_args.envelope_aad.is_none() && !plaintext {
            aad
        } else {
            updated_args.get_aad()
        };
        new_envelope.seal_and_write(output, new_aad, primitive)
    }
}

#[derive(Debug, Parser)]
pub struct CreatePublic {
    #[command(flatten)]
    pub io: IoArgs,
    #[command(flatten)]
    pub envelope_args: EnvelopeArgs,
}

impl CreatePublic {
    pub fn run<'a>(self, stdin: impl 'a + Read, stdout: impl 'a + Write) -> Result<()> {
        let CreatePublic { io, envelope_args } = self;
        let (input, mut output) = io.get(stdin, stdout)?;
        let aad = envelope_args.get_aad();
        let envelope = envelope_args.get_envelope(None)?;
        let primitive = envelope.open(aad, input)?;
        if let Primitive::Dsa(sig) = primitive {
            let public = sig.verifier();
            let jwks = serde_json::to_vec_pretty(&public)?;
            output.write_all(&jwks)?;
            output.write_all(b"\n")?;
            output.flush()?;
        } else {
            bail!("only signature keyrings support public keysets");
        }
        Ok(())
    }
}

#[derive(Debug, Parser)]
pub struct SetKeyMetadata {
    #[command(flatten)]
    pub io: IoArgs,
    #[command(flatten)]
    pub envelope_args: EnvelopeArgs,
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
    pub fn run<'a>(self, stdin: impl 'a + Read, stdout: impl 'a + Write) -> Result<()> {
        let SetKeyMetadata {
            io,
            envelope_args,
            key_id,
            metadata,
            clear_metadata,
        } = self;
        let (input, output) = io.get(stdin, stdout)?;
        let aad = envelope_args.get_aad();
        let envelope = envelope_args.get_envelope(None)?;

        let meta: Option<navajo::Metadata> = if clear_metadata {
            None
        } else {
            metadata.try_into()?
        };

        let mut primitive = envelope.open(aad.clone(), input)?;
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
        envelope.seal_and_write(output, aad, primitive)
    }
}

#[derive(Debug, Clone, Parser, Default)]
pub struct Input {
    /// The input file to read the keyring from.
    ///
    /// If not specified, stdin is used
    #[arg(value_name = "INPUT", long = "input", short = 'i')]
    pub input: Option<PathBuf>,
}
impl Input {
    pub fn get<'a>(self, stdin: impl 'a + Read) -> std::io::Result<Box<dyn 'a + Read>> {
        if let Some(input_path) = self.input {
            Ok(Box::new(std::fs::File::open(input_path)?))
        } else {
            Ok(Box::new(stdin))
        }
    }
}
#[derive(Debug, Clone, Parser, Default)]
pub struct Output {
    /// The output file to write the keyring to.
    ///
    /// If not specified, stdout is used
    #[arg(value_name = "OUTPUT", long = "output", short = 'o')]
    pub output: Option<PathBuf>,
}
impl Output {
    pub fn get<'a>(self, stdout: impl 'a + Write) -> std::io::Result<Box<dyn 'a + Write>> {
        if let Some(output_path) = self.output {
            Ok(Box::new(std::fs::File::create(output_path)?))
        } else {
            Ok(Box::new(stdout))
        }
    }
}
#[derive(Debug, Parser, Default)]
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
    pub fn get<'a>(
        self,
        stdin: impl 'a + Read,
        stdout: impl 'a + Write,
    ) -> std::io::Result<(Box<dyn 'a + Read>, Box<dyn 'a + Write>)> {
        Ok((self.input.get(stdin)?, self.output.get(stdout)?))
    }
}

#[derive(Debug, Parser, Default)]
pub struct EnvelopeArgs {
    #[arg(
        value_name = "ENVELOPE_URI",
        long = "envelope",
        short = 'e',
        alias = "envelope-uri"
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
    pub envelope: Option<Envelope>,

    /// Additional authenticated data(AAD), if any, used to authenticate the
    /// keyring. The value can either be a URI in the form
    /// <gcp|aws|azure|vault>://<key-path> or a possibly encoded (base64 or hex)
    /// string.
    ///
    /// For URIs, the path should be the secret's URI on a supported secret
    /// manager. For example, a path of:
    /// gcp://projects/my-project/secrets/my-secret/versions/1 would use the
    /// first version of the secret "my-secret" on GCP.
    ///
    /// For both secrets hosted on a secret manager and strings, the the `envelope-aad-encoding`
    /// determines if and how the value is decoded.
    #[arg(
        value_name = "ENVELOPE_AAD",
        alias = "env-aad",
        long = "envelope-aad",
        short = 's'
    )]
    pub envelope_aad: Option<Aad>,

    /// The encoding of the envelope AAD value, if any. If not specified, the
    /// value is treated as a string.
    #[arg(
        value_name = "ENVELOPE_AAD_ENCODING",
        long = "envelope-aad-encoding",
        short = 'd'
    )]
    pub envelope_aad_encoding: Option<Encoding>,
}
impl EnvelopeArgs {
    pub fn get_aad(&self) -> navajo::Aad<sensitive::Bytes> {
        match &self.envelope_aad {
            Some(aad) => aad.0.clone(),
            None => navajo::Aad(sensitive::Bytes::default()),
        }
    }
    pub fn get_envelope(&self, plaintext: Option<bool>) -> Result<Envelope> {
        match &self.envelope {
            Some(envelope) => Ok(envelope.clone()),
            None => match plaintext {
                Some(true) => Ok(Envelope::Plaintext(navajo::PlaintextJson)),
                Some(false) => bail!("Either --plaintext or --envelope must be provided"),
                None => Ok(Envelope::Plaintext(navajo::PlaintextJson)),
            },
        }
    }
}

#[cfg(test)]
mod tests {
    #[derive(Deserialize, Clone, Debug)]
    struct Key {
        id: u32,
        alg: Algorithm,
        origin: navajo::Origin,
        status: Status,
        value: serde_json::Value,
        #[serde(default)]
        pub_id: Option<String>,
        #[serde(default)]
        metadata: Option<navajo::Metadata>,
    }
    #[derive(Deserialize, Debug)]
    struct Keyring {
        keys: Vec<Key>,
        kind: navajo::Kind,
        version: u8,
    }

    use super::*;
    use anyhow::Result;
    use navajo::Status;
    use serde::Deserialize;
    use serde_json::json;
    use strum::IntoEnumIterator;
    fn run_cmd<'a>(
        cmd: impl Into<Command>,
        input: impl 'a + Read,
        output: impl 'a + Write,
    ) -> Result<()> {
        let command = cmd.into();
        let cli = Cli { command };
        cli.run(input, output)
    }

    #[test]
    fn test_new_plaintext() {
        for algorithm in Algorithm::iter() {
            let mut w = vec![];
            let r: Vec<u8> = vec![];
            let meta = json!({"example": "value"});
            let metadata = Some(serde_json::to_string(&meta).unwrap());
            let new = New {
                algorithm: algorithm.clone(),
                env_args: Default::default(),
                metadata: Metadata { metadata },
                output: Default::default(),
                plaintext: true,
                pub_id: None,
            };
            run_cmd(new, r.as_slice(), &mut w).unwrap();
            let keyring: Keyring = serde_json::from_slice(&w).unwrap();
            assert_eq!(
                keyring.keys.len(),
                1,
                "expected 1 key, found {}",
                keyring.keys.len()
            );
            let key = &keyring.keys[0];
            assert!(key.id > 0, "id is not greater than 0");

            assert_eq!(
                key.alg, algorithm,
                "expected algorithm {algorithm}, found {}",
                key.alg,
            );

            assert_eq!(key.status, Status::Primary);
            assert_eq!(keyring.version, 0);
            assert_eq!(key.origin, navajo::Origin::Navajo);
            assert_eq!(keyring.kind, algorithm.kind());

            if let Some(pub_id) = &key.pub_id {
                assert_eq!(pub_id, &key.id.to_string());
            }
            if keyring.kind.is_dsa() {
                assert!(key.value.is_array());
                let value = key.value.as_array().unwrap();
                assert_eq!(value.len(), 2);
            } else {
                assert!(key.value.is_string());
            }
            let mut expected_meta = navajo::Metadata::new();
            expected_meta
                .insert("example".into(), "value".into())
                .unwrap();
            assert_eq!(key.metadata.clone().unwrap(), expected_meta);
        }
    }

    #[test]
    fn test_add_key_plaintext() {
        for algorithm in Algorithm::iter() {
            let mut w = vec![];
            let r: Vec<u8> = vec![];
            let new = New {
                algorithm: algorithm.clone(),
                env_args: Default::default(),
                metadata: Default::default(),
                output: Default::default(),
                plaintext: true,
                pub_id: None,
            };
            run_cmd(new, r.as_slice(), &mut w).unwrap();

            let keyring: Keyring = serde_json::from_slice(&w).unwrap();
            let first_key = keyring.keys[0].clone();
            assert_eq!(first_key.status, Status::Primary);
            assert!(first_key.id > 0, "id is not greater than 0");
            let r = w;
            let mut w = vec![];

            let add = AddKey {
                algorithm: algorithm.clone(),
                envelope_args: Default::default(),
                metadata: Default::default(),
                io: Default::default(),
                pub_id: None,
            };

            run_cmd(add, r.as_slice(), &mut w).unwrap();

            let keyring: Keyring = serde_json::from_slice(&w).unwrap();
            assert_eq!(keyring.version, 0);
            assert_eq!(
                keyring.keys.len(),
                2,
                "expected 2 keys, found {}",
                keyring.keys.len()
            );
            let second_key = keyring.keys[1].clone();
            assert_ne!(second_key.id, first_key.id);
            assert_eq!(keyring.keys[0].status, Status::Primary);
            assert_eq!(second_key.status, Status::Secondary);
            assert!(second_key.id > 0, "id is not greater than 0");
            assert_eq!(second_key.alg, algorithm);
        }
    }
    #[test]
    fn test_promote_key_plaintext() {
        for algorithm in Algorithm::iter() {
            let mut w = vec![];
            let r: Vec<u8> = vec![];
            let new = New {
                algorithm: algorithm.clone(),
                env_args: Default::default(),
                metadata: Default::default(),
                output: Default::default(),
                plaintext: true,
                pub_id: None,
            };
            run_cmd(new, r.as_slice(), &mut w).unwrap();

            let keyring: Keyring = serde_json::from_slice(&w).unwrap();
            let first_key = keyring.keys[0].clone();
            assert_eq!(first_key.status, Status::Primary);
            assert!(first_key.id > 0, "id is not greater than 0");

            let r = w;
            let mut w = vec![];

            let add = AddKey {
                algorithm: algorithm.clone(),
                envelope_args: Default::default(),
                metadata: Default::default(),
                io: Default::default(),
                pub_id: None,
            };
            run_cmd(add, r.as_slice(), &mut w).unwrap();

            let keyring: Keyring = serde_json::from_slice(&w).unwrap();
            assert_eq!(keyring.version, 0);
            assert_eq!(
                keyring.keys.len(),
                2,
                "expected 2 keys, found {}",
                keyring.keys.len()
            );
            let second_key = keyring.keys[1].clone();
            assert_ne!(second_key.id, first_key.id);
            assert_eq!(keyring.keys[0].status, Status::Primary);
            assert_eq!(second_key.status, Status::Secondary);
            assert!(second_key.id > 0, "id is not greater than 0");
            assert_eq!(second_key.alg, algorithm);

            let r = w;
            let mut w = vec![];
            let promote = PromoteKey {
                key_id: second_key.id,
                io: Default::default(),
                envelope_args: Default::default(),
            };
            run_cmd(promote, r.as_slice(), &mut w).unwrap();
            let keyring: Keyring = serde_json::from_slice(&w).unwrap();
            assert_eq!(keyring.version, 0);
            assert_eq!(
                keyring.keys.len(),
                2,
                "expected 2 keys, found {}",
                keyring.keys.len()
            );

            let second_key = keyring.keys[1].clone();
            assert_ne!(second_key.id, first_key.id);
            assert_eq!(keyring.keys[0].status, Status::Secondary);
            assert_eq!(second_key.status, Status::Primary);
            assert!(second_key.id > 0, "id is not greater than 0");
            assert_eq!(second_key.alg, algorithm);
        }
    }
    #[test]
    fn test_migrate() {
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
        //
        // .unwrap()
    }
}
