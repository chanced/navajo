use std::{
    borrow::BorrowMut,
    io::{Read, Write},
    path::PathBuf,
};

use crate::{algorithm::Algorithm, envelope::Envelope, Aad, Encoding};
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

    /// Migrates a keyring to a new envelope, changes the envelope's AAD, or both.
    #[command(alias = "m")]
    Migrate(Migrate),

    /// Generates a public JWKS from a private, asymmetric keyring.
    #[command(alias = "create_public")]
    CreatePublic(CreatePublic),

    /// Adds a new key to a keyring.
    #[command(alias = "add_key", alias = "add", alias = "a")]
    AddKey(AddKey),

    /// Promotes a key to primary in a keyring.
    #[command(alias = "promote_key", alias = "promote", alias = "p")]
    PromoteKey(PromoteKey),

    /// Enables a disabled key in a keyring.
    #[command(alias = "enable_key", alias = "enable", alias = "e")]
    EnableKey(EnableKey),

    /// Disables a key in a keyring. Disabling a key effectively removes
    /// the key from the keyring, but leaves it in a recoverable state.
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

#[derive(Debug, Parser)]
pub struct New {
    /// Specifies the algorithm to use for the first key in the keyring.
    pub algorithm: Algorithm,
    #[command(flatten)]
    pub metadata: Metadata,
    #[command(flatten)]
    pub output: Output,
    #[command(flatten)]
    pub integration: EnvelopeArgs,
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
            integration: env_args,
            output,
            metadata,
            pub_id,
            plaintext,
        } = self;
        if env_args.envelope_uri.is_none() && !plaintext {
            bail!("Either --plaintext or --kms-key-uri must be provided");
        }

        let output = output.get(stdout)?;
        let envelope = env_args.get_envelope()?;
        let aad = env_args.get_aad()?;
        let metadata = metadata.try_into()?;

        let primitive = match algorithm.kind() {
            Kind::Aead => Primitive::Aead(Aead::new(algorithm.try_into()?, metadata)),
            Kind::Daead => Primitive::Daead(Daead::new(algorithm.try_into()?, metadata)),
            Kind::Mac => Primitive::Mac(Mac::new(algorithm.try_into()?, metadata)),
            Kind::Signature => Primitive::Dsa(Signer::new(algorithm.try_into()?, pub_id, metadata)),
        };
        envelope.seal_and_write(output, aad, primitive)
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
    pub envelope: EnvelopeArgs,
}

impl Inspect {
    pub fn run<'a>(self, stdin: impl 'a + Read, stdout: impl 'a + Write) -> Result<()> {
        let Inspect { io, envelope } = self;
        let (input, mut output) = io.get(stdin, stdout)?;
        let aad = envelope.get_aad()?;
        let envelope = envelope.get_envelope()?;
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
    #[command(flatten)]
    pub metadata: Metadata,
    #[arg(value_name = "PUB_ID", long = "public-id", short = 'p')]
    pub_id: Option<String>,
}

impl AddKey {
    pub fn run<'a>(self, stdin: impl 'a + Read, stdout: impl 'a + Write) -> Result<()> {
        let AddKey {
            io,
            envelope,
            algorithm,
            metadata,
            pub_id,
        } = self;
        let (input, output) = io.get(stdin, stdout)?;
        let aad = envelope.get_aad()?;
        let envelope = envelope.get_envelope()?;
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
    pub envelope: EnvelopeArgs,
    /// The ID of the key to operate on.
    pub key_id: u32,
}
impl PromoteKey {
    pub fn run<'a>(self, stdin: impl 'a + Read, stdout: impl 'a + Write) -> Result<()> {
        let PromoteKey {
            io,
            envelope,
            key_id,
        } = self;
        let (input, output) = io.get(stdin, stdout)?;
        let aad = envelope.get_aad()?;
        let envelope = envelope.get_envelope()?;
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
    pub envelope: EnvelopeArgs,
    /// The ID of the key to operate on.
    pub key_id: u32,
}
impl EnableKey {
    pub fn run<'a>(self, stdin: impl 'a + Read, stdout: impl 'a + Write) -> Result<()> {
        let EnableKey {
            io,
            envelope,
            key_id,
        } = self;
        let (input, output) = io.get(stdin, stdout)?;
        let aad = envelope.get_aad()?;
        let envelope = envelope.get_envelope()?;
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
    pub envelope: EnvelopeArgs,
    /// The ID of the key to operate on.
    pub key_id: u32,
}
impl DisableKey {
    pub fn run<'a>(self, stdin: impl 'a + Read, stdout: impl 'a + Write) -> Result<()> {
        let DisableKey {
            io,
            envelope,
            key_id,
        } = self;
        let (input, output) = io.get(stdin, stdout)?;
        let aad = envelope.get_aad()?;
        let envelope = envelope.get_envelope()?;
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
    pub envelope: EnvelopeArgs,
    /// The ID of the key to operate on.
    pub key_id: u32,
}
impl DeleteKey {
    pub fn run<'a>(self, stdin: impl 'a + Read, stdout: impl 'a + Write) -> Result<()> {
        let DeleteKey {
            io,
            envelope,
            key_id,
        } = self;
        let (input, output) = io.get(stdin, stdout)?;
        let aad = envelope.get_aad()?;
        let envelope = envelope.get_envelope()?;
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
    integration: EnvelopeArgs,

    /// The new URI to a crypto key in a KMS to use as envelope encryption for
    /// the keyring.
    ///
    /// If not specified, the keyring will be re-encrypted with the same key (if any).
    #[arg(value_name = "NEW_ENVELOPE", long = "new-envelope")]
    pub new_key_uri: Option<Url>,

    /// The new URI to a secret in a cloud secret manager to be used as
    /// additional authenticated data for the keyring.
    #[arg(value_name = "NEW_ENVELOPE_AAD", long = "new-envelope-aad")]
    pub new_envelope_aad: Option<Aad>,

    #[arg(
        value_name = "NEW_ENVELOPE_AAD_ENCODING",
        long = "new-envelope-aad-encoding"
    )]
    pub new_envelope_aad_encoding: Option<Encoding>,

    /// Disables encryption, outputting the keyring as plaintext JSON.
    #[arg(value_name = "PLAINTEXT", long = "plaintext")]
    pub plaintext: bool,
}

impl Migrate {
    pub fn run<'a>(self, stdin: impl 'a + Read, stdout: impl 'a + Write) -> Result<()> {
        let Migrate {
            integration,
            io,
            new_key_uri,
            new_envelope_aad,
            plaintext,
            new_envelope_aad_encoding,
        } = self;
        let (input, output) = io.get(stdin, stdout)?;
        let aad = integration.get_aad()?;
        let envelope = integration.get_envelope()?;
        let primitive = envelope.open(aad.clone(), input)?;

        let updated_args = EnvelopeArgs {
            envelope_aad: new_envelope_aad,
            envelope_uri: new_key_uri,
            envelope_aad_encoding: new_envelope_aad_encoding,
        };

        let new_envelope = if updated_args.envelope_uri.is_none() && !plaintext {
            envelope
        } else {
            updated_args.get_envelope()?
        };
        let new_aad = if updated_args.envelope_aad.is_none() && !plaintext {
            aad
        } else {
            updated_args.get_aad()?
        };
        new_envelope.seal_and_write(output, new_aad, primitive)
    }
}

#[derive(Debug, Parser)]
pub struct CreatePublic {
    #[command(flatten)]
    pub io: IoArgs,
    #[command(flatten)]
    pub integration: EnvelopeArgs,
}

impl CreatePublic {
    pub fn run<'a>(self, stdin: impl 'a + Read, stdout: impl 'a + Write) -> Result<()> {
        let CreatePublic {
            io,
            integration: envelope,
        } = self;
        let (input, mut output) = io.get(stdin, stdout)?;
        let aad = envelope.get_aad()?;
        let envelope = envelope.get_envelope()?;
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
    pub integration: EnvelopeArgs,
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
            integration: envelope,
            key_id,
            metadata,
            clear_metadata,
        } = self;
        let (input, output) = io.get(stdin, stdout)?;
        let aad = envelope.get_aad()?;
        let envelope = envelope.get_envelope()?;

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

#[derive(Debug, Clone, Parser)]
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
#[derive(Debug, Clone, Parser)]
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
    pub fn get<'a>(
        self,
        stdin: impl 'a + Read,
        stdout: impl 'a + Write,
    ) -> std::io::Result<(Box<dyn 'a + Read>, Box<dyn 'a + Write>)> {
        Ok((self.input.get(stdin)?, self.output.get(stdout)?))
    }
}

#[derive(Debug, Parser)]
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
    pub envelope_uri: Option<Url>,

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
    pub fn get_envelope(&self) -> Result<Envelope> {
        todo!("...")
    }

    pub fn get_aad(&self) -> Result<navajo::Aad<sensitive::Bytes>> {
        if let Some(aad) = &self.envelope_aad {
            aad.value()
        } else {
            Ok(navajo::Aad(sensitive::Bytes::default()))
        }
    }
}

#[cfg(test)]
mod tests {

    use strum::IntoEnumIterator;

    use super::*;

    #[test]
    fn test_new_plaintext() {
        for alg in Algorithm::iter() {
            let mut w = vec![];
            let r: Vec<u8> = vec![];
            let new = New {
                algorithm: alg,
                integration: EnvelopeArgs {
                    envelope_uri: None,
                    envelope_aad: None,
                    envelope_aad_encoding: None,
                },
                metadata: Metadata { metadata: None },
                output: Output { output: None },
                plaintext: true,
                pub_id: None,
            };
            let cli = Cli {
                command: Command::New(new),
            };
            cli.run(r.as_slice(), &mut w).unwrap();
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
