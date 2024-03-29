use std::{
    borrow::BorrowMut,
    fs,
    io::{Read, Write},
    path::PathBuf,
};

use crate::{
    algorithm::Algorithm, envelope::Envelope, Aad, Encoding, EncodingReader, EncodingWriter,
    Segment,
};
use anyhow::{bail, Context, Result};
use clap::{Parser, Subcommand};
use navajo::{sensitive, Aead, Daead, Kind, Mac, Primitive, Signer};

pub fn proxy_env(src: &str, dst: &str) {
    let src = src.to_uppercase();
    let dst = dst.to_uppercase();
    if let Ok(value) = std::env::var(src) {
        if std::env::var(&dst).is_err() {
            std::env::set_var(&dst, value);
        }
    }
}

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
    pub fn setup() -> Self {
        proxy_env("NAVAJO_IN", "NAVAJO_INPUT");
        proxy_env("NAVAJO_OUT", "NAVAJO_OUTPUT");
        proxy_env("NAVAJO_IN_ENCODING", "NAVAJO_INPUT_ENCODING");
        proxy_env("NAVAJO_OUT_ENCODING", "NAVAJO_OUTPUT_ENCODING");
        proxy_env("NAVAJO_ENVELOPE_URI", "NAVAJO_ENVELOPE");
        Self::parse()
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
    #[command(alias = "enable_key", alias = "enable")]
    EnableKey(EnableKey),

    /// Disables a key in a keyring.
    #[command(alias = "disable_key", alias = "disable")]
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

    /// Encrypt a file or stdin using an AEAD keyring.
    #[command(alias = "e")]
    Encrypt(Encrypt),

    /// Decrypt a file or stdin using an AEAD keyring.
    #[command(alias = "d")]
    Decrypt(Decrypt),
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
            Command::Encrypt(cmd) => cmd.run(stdin, stdout),
            Command::Decrypt(cmd) => cmd.run(stdin, stdout),
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
impl From<Encrypt> for Command {
    fn from(cmd: Encrypt) -> Self {
        Command::Encrypt(cmd)
    }
}
impl From<Decrypt> for Command {
    fn from(cmd: Decrypt) -> Self {
        Command::Decrypt(cmd)
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
    pub io: Io,
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
        let json = serde_json::to_vec_pretty(&primitive.info())?;
        output.write_all(&json)?;
        let mut output = output.into_inner()?;
        // output.write_all(b"\n")?; https://github.com/marshallpierce/rust-base64/issues/236
        output.flush()?;
        Ok(())
    }
}

#[derive(Debug, Parser)]
pub struct AddKey {
    #[command(flatten)]
    pub io: Io,
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
    pub io: Io,
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
    pub io: Io,
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
                aead.enable(key_id).context("failed to enable key")?;
            }
            Primitive::Daead(daead) => {
                daead.enable(key_id).context("failed to enable key")?;
            }
            Primitive::Mac(mac) => {
                mac.enable(key_id).context("failed to enable key")?;
            }
            Primitive::Dsa(sig) => {
                sig.enable(key_id).context("failed to enable key")?;
            }
        }
        envelope.seal_and_write(output, aad, primitive)
    }
}
#[derive(Debug, Parser)]
pub struct DisableKey {
    #[command(flatten)]
    pub io: Io,
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
                aead.disable(key_id).context("failed to disable key")?;
            }
            Primitive::Daead(daead) => {
                daead.disable(key_id).context("failed to disable key")?;
            }
            Primitive::Mac(mac) => {
                mac.disable(key_id).context("failed to disable key")?;
            }
            Primitive::Dsa(sig) => {
                sig.disable(key_id).context("failed to disable key")?;
            }
        }
        envelope.seal_and_write(output, aad, primitive)
    }
}

#[derive(Debug, Parser)]
pub struct DeleteKey {
    #[command(flatten)]
    pub io: Io,
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
                aead.delete(key_id).context("failed to delete key")?;
            }
            Primitive::Daead(daead) => {
                daead.delete(key_id).context("failed to delete key")?;
            }
            Primitive::Mac(mac) => {
                mac.delete(key_id).context("failed to delete key")?;
            }
            Primitive::Dsa(sig) => {
                sig.delete(key_id).context("failed to delete key")?;
            }
        }
        envelope.seal_and_write(output, aad, primitive)
    }
}

#[derive(Debug, Parser)]
pub struct Migrate {
    #[command(flatten)]
    io: Io,

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
    pub io: Io,
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
            let mut output = output.into_inner()?;
            // output.write_all(b"\n")?; https://github.com/marshallpierce/rust-base64/issues/236
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
    pub io: Io,
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

#[derive(Debug, Parser)]
pub struct Encrypt {
    #[command(flatten)]
    pub io: Io,
    #[command(flatten)]
    pub envelope_args: EnvelopeArgs,
    #[arg(
        value_name = "SEGMENT_SIZE",
        long = "segment",
        short = 's',
        env = "NAVAJO_SEGMENT_SIZE"
    )]
    pub segment: Segment,

    #[arg(
        value_name = "AEAD_KEYRING",
        long = "keyring",
        alias = "aead",
        short = 'k',
        env = "NAVAJO_AEAD_KEYRING"
    )]
    pub keyring: PathBuf,

    #[arg(
        value_name = "AEAD_KEYRING_ENCODING",
        long = "keyring-encoding",
        alias = "aead-encoding",
        short = 'K',
        env = "NAVAJO_AEAD_KEYRING_ENCODING"
    )]
    pub keyring_encoding: Option<Encoding>,
}

impl Encrypt {
    pub fn run<'a>(self, stdin: impl 'a + Read, stdout: impl 'a + Write) -> Result<()> {
        let Encrypt {
            io,
            envelope_args,
            segment,
            keyring,
            keyring_encoding,
        } = self;
        let (mut input, mut output) = io.get(stdin, stdout)?;
        let keyring = fs::File::open(keyring)?;

        let aad = envelope_args.get_aad();
        let envelope = envelope_args.get_envelope(None)?;

        let keyring = if let Some(encoding) = keyring_encoding {
            encoding.decode_reader(keyring)
        } else {
            EncodingReader::None(keyring)
        };
        let primitive = envelope.open(aad.clone(), keyring)?;

        if let Some(aead) = primitive.aead() {
            aead.encrypt_writer(&mut output, aad, segment.into(), |w| {
                std::io::copy(&mut input, w)?;
                Ok(())
            })?;
            Ok(())
        } else {
            bail!("only AEAD keyrings support encryption");
        }
    }
}

#[derive(Debug, Parser)]
pub struct Decrypt {
    #[command(flatten)]
    pub io: Io,
    #[command(flatten)]
    pub envelope_args: EnvelopeArgs,

    #[arg(
        value_name = "AEAD_KEYRING",
        long = "keyring",
        alias = "aead",
        short = 'k',
        env = "NAVAJO_AEAD_KEYRING"
    )]
    pub keyring: PathBuf,

    #[arg(
        value_name = "AEAD_KEYRING_ENCODING",
        long = "keyring-encoding",
        alias = "aead-encoding",
        short = 'K',
        env = "NAVAJO_AEAD_KEYRING_ENCODING"
    )]
    pub keyring_encoding: Option<Encoding>,
}

impl Decrypt {
    pub fn run<'a>(self, stdin: impl 'a + Read, stdout: impl 'a + Write) -> Result<()> {
        let Decrypt {
            io,
            envelope_args,
            keyring,
            keyring_encoding,
        } = self;
        let (mut input, mut output) = io.get(stdin, stdout)?;
        let keyring = fs::File::open(keyring)?;

        let aad = envelope_args.get_aad();
        let envelope = envelope_args.get_envelope(None)?;

        let keyring = if let Some(encoding) = keyring_encoding {
            encoding.decode_reader(keyring)
        } else {
            EncodingReader::None(keyring)
        };
        let primitive = envelope.open(aad.clone(), keyring)?;

        if let Some(aead) = primitive.aead() {
            let mut reader = aead.decrypt_reader(&mut input, aad);
            std::io::copy(&mut reader, &mut output)?;
            Ok(())
        } else {
            bail!("only AEAD keyrings support encryption");
        }
    }
}

#[derive(Debug, Clone, Parser, Default)]
pub struct Input {
    /// The input file to read the keyring from.
    ///
    /// If not specified, stdin is used
    #[arg(
        value_name = "INPUT",
        env = "NAVAJO_INPUT",
        long = "in",
        short = 'i',
        alias = "input"
    )]
    pub input: Option<PathBuf>,
    /// The encoding to use for input file.
    #[arg(
        value_name = "INPUT_ENCODING",
        env = "NAVAJO_INPUT_ENCODING",
        long = "in-encoding",
        alias = "input-encoding",
        short = 'I'
    )]
    pub input_encoding: Option<Encoding>,
}

impl Input {
    pub fn get<'a>(self, stdin: impl 'a + Read) -> Result<EncodingReader<Box<dyn 'a + Read>>> {
        let r: Box<dyn Read> = if let Some(input_path) = self.input {
            Box::new(std::fs::File::open(input_path)?)
        } else {
            Box::new(stdin)
        };
        if let Some(encoding) = self.input_encoding {
            Ok(encoding.decode_reader(r))
        } else {
            Ok(EncodingReader::None(r))
        }
    }
}
#[derive(Debug, Clone, Parser, Default)]
pub struct Output {
    /// The output file for keyrings or other cryptographic operations. If not
    /// specified, stdout is used.s
    #[arg(
        value_name = "OUTPUT",
        env = "NAVAJO_OUTPUT",
        long = "out",
        short = 'o'
    )]
    pub output: Option<PathBuf>,
    /// The encoding to use for the output file.
    #[arg(
        value_name = "OUTPUT_ENCODING",
        env = "NAVAJO_OUTPUT_ENCODING",
        long = "out-encoding",
        alias = "output-encoding",
        short = 'O'
    )]
    pub out_encoding: Option<Encoding>,

    /// if set and OUTPUT_ENCODING is set to base64 or base64url then padding
    /// will be added
    #[arg(
        value_name = "PAD_OUTPUT_ENCODING",
        env = "NAVAJO_PAD_OUTPUT_ENCODING",
        long = "pad-out-encoding",
        alias = "pad-out-encoding",
        short = 'P'
    )]
    pub pad_out_encoding: bool,
}
impl Output {
    pub fn get<'a>(
        self,
        stdout: impl 'a + Write,
    ) -> std::io::Result<EncodingWriter<Box<dyn 'a + Write>>> {
        let boxed_out: Box<dyn Write> = if let Some(output_path) = self.output {
            if let Some(parent) = output_path.parent() {
                std::fs::create_dir_all(parent)?
            }
            Box::new(std::fs::File::create(output_path)?)
        } else {
            Box::new(stdout)
        };
        if let Some(encoding) = self.out_encoding {
            Ok(encoding.encode_writer(boxed_out, self.pad_out_encoding))
        } else {
            Ok(EncodingWriter::None(Some(boxed_out)))
        }
    }
}

#[derive(Debug, Parser, Default)]
pub struct Io {
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
#[allow(clippy::type_complexity)]
impl Io {
    pub fn get<'a>(
        self,
        stdin: impl 'a + Read,
        stdout: impl 'a + Write,
    ) -> Result<(
        EncodingReader<Box<dyn 'a + Read>>,
        EncodingWriter<Box<dyn 'a + Write>>,
    )> {
        Ok((self.input.get(stdin)?, self.output.get(stdout)?))
    }
}

#[derive(Debug, Parser, Default)]
pub struct EnvelopeArgs {
    #[arg(
        value_name = "ENVELOPE_URI",
        env = "NAVAJO_ENVELOPE",
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
    /// - \033[1mGCP\033[0m:   gcp://projects/<project-id>/locations/<location>/keyRings/<keyring-id>/cryptoKeys/<key-id>
    /// - AWS:   aws://arn:aws:kms:<region>:<account-id>:key/<key-id>
    /// - JSON:  json://<path-to-json-file>
    ///
    ///
    #[clap(verbatim_doc_comment)]
    pub envelope: Option<Envelope>,

    /// Additional authenticated data(AAD), if any, used to authenticate the
    /// keyring.
    ///
    /// The value can either be a URI in the form
    ///<gcp|aws|azure|vault>://<key-path> or a possibly encoded (base64 or hex)
    /// string.
    ///
    /// For URIs, the path should be the secret's URI on a supported secret
    /// manager. For example, a path of:
    /// gcp://projects/my-project/secrets/my-secret/versions/1 would use the
    /// first version of the secret "my-secret" on GCP.
    ///
    /// For both secrets hosted on a secret manager and strings, the the
    /// `envelope-aad-encoding` determines if and how the value is decoded.
    #[arg(
        value_name = "ENVELOPE_AAD",
        alias = "env-aad",
        long = "envelope-aad",
        short = 'E'
    )]
    pub envelope_aad: Option<Aad>,

    /// The encoding of the envelope AAD value, if any. If not specified, the
    /// value is treated as a string.
    #[arg(
        value_name = "ENVELOPE_AAD_ENCODING",
        long = "envelope-aad-encoding",
        short = 'A',
        env = "NAVAJO_ENVELOPE_AAD_ENCODING"
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

// =======================================================================================================
// =======================================================================================================
// ================================================ Tests ================================================
// =======================================================================================================
// =======================================================================================================

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

    use std::str::FromStr;

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
        let cli: Cli = cmd.into().into();
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
                algorithm,
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
                algorithm,
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

            let add = AddKey {
                algorithm,
                envelope_args: Default::default(),
                metadata: Default::default(),
                io: Default::default(),
                pub_id: None,
            };

            let r = w;
            let mut w = vec![];

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
            assert_eq!(second_key.status, Status::Enabled);
            assert!(second_key.id > 0, "id is not greater than 0");
            assert_eq!(second_key.alg, algorithm);

            let kind = algorithm.kind();

            // getting coverage for the is_* methods
            let algo = if kind.is_aead() {
                Algorithm::Blake3
            } else if kind.is_daead() {
                Algorithm::Ed25519
            } else if kind.is_dsa() {
                Algorithm::Aes_256_Gcm
            } else if kind.is_mac() {
                Algorithm::Aes_256_Siv
            } else {
                panic!("unknown kind {:?}", kind);
            };

            let add_key = AddKey {
                algorithm: algo,
                envelope_args: Default::default(),
                metadata: Default::default(),
                io: Default::default(),
                pub_id: None,
            };
            let r = w;
            let mut w = vec![];
            assert!(run_cmd(add_key, r.as_slice(), &mut w).is_err());
        }
    }
    #[test]
    fn test_promote_key_plaintext() {
        for algorithm in Algorithm::iter() {
            let mut w = vec![];
            let r: Vec<u8> = vec![];
            let new = New {
                algorithm,
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
                algorithm,
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
            assert_eq!(second_key.status, Status::Enabled);
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
            assert_eq!(keyring.keys[0].status, Status::Enabled);
            assert_eq!(second_key.status, Status::Primary);
            assert!(second_key.id > 0, "id is not greater than 0");
            assert_eq!(second_key.alg, algorithm);
        }
    }

    #[test]
    fn test_inspect() {
        for algorithm in Algorithm::iter() {
            let mut w = vec![];
            let r: Vec<u8> = vec![];
            let meta = json!({"example": "value"});
            let metadata = Some(serde_json::to_string(&meta).unwrap());
            let new = New {
                algorithm,
                env_args: Default::default(),
                metadata: Metadata { metadata },
                output: Default::default(),
                plaintext: true,
                pub_id: None,
            };

            run_cmd(new, r.as_slice(), &mut w).unwrap();

            let keyring: Keyring = serde_json::from_slice(&w).unwrap();
            let key = keyring.keys.get(0).ok_or("invalid number of keys").unwrap();
            let mut expected_meta = navajo::Metadata::new();
            expected_meta
                .insert("example".into(), "value".into())
                .unwrap();
            assert_eq!(key.metadata.clone().unwrap(), expected_meta);

            let r = w;
            let mut w = vec![];

            run_cmd(
                Inspect {
                    io: Default::default(),
                    envelope_args: Default::default(),
                },
                r.as_slice(),
                &mut w,
            )
            .unwrap();

            let keyring_info: navajo::primitive::KeyringInfo = serde_json::from_slice(&w).unwrap();
            assert_eq!(keyring_info.version(), 0);
            assert_eq!(keyring_info.kind(), algorithm.kind());
            match algorithm.kind() {
                Kind::Aead => {
                    let info = keyring_info.aead().unwrap();
                    assert_eq!(info.keys.len(), 1);
                    assert_eq!(info.keys[0].id, key.id);
                    assert_eq!(info.keys[0].status, key.status);
                }
                Kind::Daead => {
                    let info = keyring_info.daead().unwrap();
                    assert_eq!(info.keys.len(), 1);
                    assert_eq!(info.keys[0].id, key.id);
                    assert_eq!(info.keys[0].status, key.status);
                }
                Kind::Mac => {
                    let info = keyring_info.mac().unwrap();
                    assert_eq!(info.keys.len(), 1);
                    assert_eq!(info.keys[0].id, key.id);
                    assert_eq!(info.keys[0].status, key.status);
                }
                Kind::Dsa => {
                    let info = keyring_info.dsa().unwrap();
                    assert_eq!(info.keys.len(), 1);
                    assert_eq!(info.keys[0].id, key.id);
                    assert_eq!(info.keys[0].status, key.status);
                }
            }
        }
    }
    #[test]
    fn test_disable_key_enable_key() {
        for algorithm in Algorithm::iter() {
            let mut w = vec![];
            let r: Vec<u8> = vec![];
            let new = New {
                algorithm,
                env_args: Default::default(),
                metadata: Default::default(),
                output: Default::default(),
                plaintext: true,
                pub_id: None,
            };
            run_cmd(new, r.as_slice(), &mut w).unwrap();

            let keyring_data = w.clone();

            let keyring: Keyring = serde_json::from_slice(&w).unwrap();

            let first_key = keyring.keys[0].clone();
            assert_eq!(first_key.status, Status::Primary);

            let disable_key = DisableKey {
                key_id: first_key.id,
                io: Default::default(),
                envelope_args: Default::default(),
            };
            assert!(run_cmd(disable_key, r.as_slice(), &mut w).is_err());

            let add_key = AddKey {
                algorithm,
                envelope_args: Default::default(),
                metadata: Default::default(),
                io: Default::default(),
                pub_id: None,
            };

            let r = keyring_data;
            let mut w = vec![];

            run_cmd(add_key, r.as_slice(), &mut w).unwrap();
            let keyring_data = w.clone();

            let keyring: Keyring = serde_json::from_slice(&w).unwrap();
            let second_key = &keyring.keys[1];

            let disable_key = DisableKey {
                key_id: first_key.id,
                io: Default::default(),
                envelope_args: Default::default(),
            };

            let r = w;
            let mut w = vec![];
            assert!(run_cmd(disable_key, r.as_slice(), &mut w).is_err());

            let r = keyring_data.clone();
            let mut w = vec![];
            let disable_key = DisableKey {
                key_id: second_key.id,
                io: Default::default(),
                envelope_args: Default::default(),
            };
            run_cmd(disable_key, r.as_slice(), &mut w).unwrap();

            let keyring: Keyring = serde_json::from_slice(&w).unwrap();

            assert_eq!(keyring.keys.len(), 2);
            assert_eq!(keyring.keys[0].status, Status::Primary);
            assert_eq!(keyring.keys[1].status, Status::Disabled);

            let enable_key = EnableKey {
                key_id: second_key.id,
                io: Default::default(),
                envelope_args: Default::default(),
            };

            let r = w;
            let mut w = vec![];

            run_cmd(enable_key, r.as_slice(), &mut w).unwrap();

            let keyring: Keyring = serde_json::from_slice(&w).unwrap();

            assert_eq!(keyring.keys.len(), 2);
            assert_eq!(keyring.keys[0].status, Status::Primary);
            assert_eq!(keyring.keys[1].status, Status::Enabled);
        }
    }
    #[test]
    fn test_delete_key() {
        for algorithm in Algorithm::iter() {
            let mut w = vec![];
            let r: Vec<u8> = vec![];
            let new = New {
                algorithm,
                env_args: Default::default(),
                metadata: Default::default(),
                output: Default::default(),
                plaintext: true,
                pub_id: None,
            };
            run_cmd(new, r.as_slice(), &mut w).unwrap();

            let keyring_data = w.clone();

            let keyring: Keyring = serde_json::from_slice(&w).unwrap();

            let first_key = keyring.keys[0].clone();
            assert_eq!(first_key.status, Status::Primary);

            let delete_key = DeleteKey {
                key_id: first_key.id,
                io: Default::default(),
                envelope_args: Default::default(),
            };
            assert!(run_cmd(delete_key, r.as_slice(), &mut w).is_err());

            let add_key = AddKey {
                algorithm,
                envelope_args: Default::default(),
                metadata: Default::default(),
                io: Default::default(),
                pub_id: None,
            };

            let r = keyring_data;
            let mut w = vec![];

            run_cmd(add_key, r.as_slice(), &mut w).unwrap();
            let keyring_data = w.clone();

            let keyring: Keyring = serde_json::from_slice(&w).unwrap();
            let second_key = &keyring.keys[1];

            let delete_key = DeleteKey {
                key_id: first_key.id,
                io: Default::default(),
                envelope_args: Default::default(),
            };

            let r = w;
            let mut w = vec![];
            assert!(run_cmd(delete_key, r.as_slice(), &mut w).is_err());

            let r = keyring_data.clone();
            let mut w = vec![];
            let delete_key = DeleteKey {
                key_id: second_key.id,
                io: Default::default(),
                envelope_args: Default::default(),
            };
            run_cmd(delete_key, r.as_slice(), &mut w).unwrap();

            let keyring: Keyring = serde_json::from_slice(&w).unwrap();

            assert_eq!(keyring.keys.len(), 1);
            assert_eq!(keyring.keys[0].status, Status::Primary);
        }
    }
    #[test]
    fn test_add_key_json() {
        let rng = navajo::rand::SystemRng;
        for algorithm in Algorithm::iter() {
            let mut w = vec![];
            let r: Vec<u8> = vec![];
            let new = New {
                algorithm,
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
            let mut tmp_dir = std::env::temp_dir();
            tmp_dir.push(rng.u64().unwrap().to_string() + ".json");

            let add = AddKey {
                algorithm,
                envelope_args: Default::default(),
                metadata: Default::default(),
                io: Default::default(),
                pub_id: None,
            };

            let r = w;
            let mut w = vec![];

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
            assert_eq!(second_key.status, Status::Enabled);
            assert!(second_key.id > 0, "id is not greater than 0");
            assert_eq!(second_key.alg, algorithm);

            let kind = algorithm.kind();

            // getting coverage for the is_* methods
            let algo = if kind.is_aead() {
                Algorithm::Blake3
            } else if kind.is_daead() {
                Algorithm::Ed25519
            } else if kind.is_dsa() {
                Algorithm::Aes_256_Gcm
            } else if kind.is_mac() {
                Algorithm::Aes_256_Siv
            } else {
                panic!("unknown kind {:?}", kind);
            };

            let add_key = AddKey {
                algorithm: algo,
                envelope_args: Default::default(),
                metadata: Default::default(),
                io: Default::default(),
                pub_id: None,
            };
            let r = w;
            let mut w = vec![];
            assert!(run_cmd(add_key, r.as_slice(), &mut w).is_err());
        }
    }
    #[test]
    fn test_encrypt_decrypt() {
        let tmp = std::env::temp_dir();
        let rng = navajo::rand::SystemRng;
        let tmp = tmp.join(rng.u64().unwrap().to_string());
        std::fs::create_dir(&tmp).unwrap();
        let license_path = PathBuf::from("../LICENSE-MIT");
        let mut license = std::fs::File::open(license_path.clone()).unwrap();
        let mut license_content = vec![];
        license.read_to_end(&mut license_content).unwrap();

        for envelope_algorithm in navajo::aead::Algorithm::iter() {
            let envelope_path = tmp.join("envelope").join(envelope_algorithm.to_string());

            let mut w = vec![];
            let r: Vec<u8> = vec![];
            let new = New {
                algorithm: envelope_algorithm.into(),
                env_args: Default::default(),
                metadata: Default::default(),
                output: Output {
                    output: envelope_path.clone().into(),
                    out_encoding: None,
                    pad_out_encoding: false,
                },
                plaintext: true,
                pub_id: None,
            };

            run_cmd(new, r.as_slice(), &mut w).unwrap();

            for keyring_algorithm in Algorithm::iter() {
                let keyring_path = tmp.join("keyring").join(keyring_algorithm.to_string());
                let new = New {
                    algorithm: keyring_algorithm,
                    env_args: EnvelopeArgs {
                        envelope: Envelope::from_str(envelope_path.to_str().unwrap())
                            .unwrap()
                            .into(),
                        ..Default::default()
                    },
                    metadata: Default::default(),
                    output: Output {
                        output: keyring_path.clone().into(),
                        out_encoding: None,
                        pad_out_encoding: false,
                    },
                    plaintext: false,
                    pub_id: None,
                };

                let mut w = vec![];
                let r: Vec<u8> = vec![];

                run_cmd(new, r.as_slice(), &mut w).unwrap();

                let encrypt = Encrypt {
                    envelope_args: EnvelopeArgs {
                        envelope: Envelope::from_str(envelope_path.to_str().unwrap())
                            .unwrap()
                            .into(),
                        ..Default::default()
                    },
                    io: Io {
                        input: Input {
                            input: license_path.clone().into(),
                            ..Default::default()
                        },
                        ..Default::default()
                    },
                    segment: Segment::FourKilobytes,
                    keyring: keyring_path.clone(),
                    keyring_encoding: None,
                };

                let r = w;
                let mut w = vec![];

                let result = run_cmd(encrypt, r.as_slice(), &mut w);

                if keyring_algorithm.kind().is_aead() {
                    assert!(result.is_ok());
                    assert_ne!(w, license_content);
                } else {
                    assert!(result.is_err());
                    continue;
                }

                let decrypt = Decrypt {
                    envelope_args: EnvelopeArgs {
                        envelope: Envelope::from_str(envelope_path.to_str().unwrap())
                            .unwrap()
                            .into(),
                        ..Default::default()
                    },
                    io: Default::default(),
                    keyring: keyring_path.clone(),
                    keyring_encoding: None,
                };

                let r = w;
                let mut w = vec![];

                let result = run_cmd(decrypt, r.as_slice(), &mut w);

                if keyring_algorithm.kind().is_aead() {
                    assert!(result.is_ok());
                } else {
                    assert!(result.is_err());
                    continue;
                }
                assert_eq!(w, license_content);
            }
        }
        let _ = std::fs::remove_dir(tmp);
    }
}

// SetKeyMetadata(SetKeyMetadata),
// CreatePublic(CreatePublic),
