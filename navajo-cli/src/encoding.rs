use std::collections::VecDeque;
use std::io::{Read, Write};
use std::str::FromStr;

use anyhow::{bail, Context};
use base64::engine::{DecodePaddingMode, GeneralPurpose, GeneralPurposeConfig};
use base64::read::DecoderReader as Base64Reader;
use base64::write::EncoderWriter as Base64Writer;
use base64::Engine;
use clap::ValueEnum;

const BASE64_STANDARD: GeneralPurpose = GeneralPurpose::new(
    &base64::alphabet::STANDARD,
    GeneralPurposeConfig::new()
        .with_encode_padding(false)
        .with_decode_padding_mode(DecodePaddingMode::Indifferent),
);
const BASE64_URL_SAFE: GeneralPurpose = GeneralPurpose::new(
    &base64::alphabet::URL_SAFE,
    GeneralPurposeConfig::new()
        .with_encode_padding(false)
        .with_decode_padding_mode(DecodePaddingMode::Indifferent),
);

#[derive(Clone, Copy, PartialEq, Eq, Debug, ValueEnum, strum::Display, strum::EnumIter)]
#[strum(serialize_all = "lowercase")]
/// The encoding of a value, used for determining how to encode or decode a value.
///
/// The encoded output will always be NO_PAD
///
/// For Base64 and Base64Url, padding is indifferent for decoding
///
pub enum Encoding {
    /// Base64 encoding; output is NO_PAD but input can be with or without padding
    Base64,
    /// Base64 URL encoding; output is NO_PAD but input can be with or without padding
    #[strum(serialize = "base64url")]
    Base64url,
    /// Hex encoding
    Hex,
}

impl Encoding {
    pub fn encode<T>(&self, value: T) -> String
    where
        T: AsRef<[u8]>,
    {
        match self {
            Encoding::Hex => Self::encode_hex(value.as_ref()),
            Encoding::Base64 => Self::encode_base64(value.as_ref()),
            Encoding::Base64url => Self::encode_base64_url(value.as_ref()),
        }
    }

    pub fn decode<T>(&self, value: T) -> anyhow::Result<Vec<u8>>
    where
        T: AsRef<[u8]>,
    {
        match self {
            Encoding::Hex => Self::decode_hex(value.as_ref()),
            Encoding::Base64 => Self::decode_base64(value.as_ref()),
            Encoding::Base64url => Self::decode_base64_url(value.as_ref()),
        }
    }
    pub fn encode_writer<W: Write>(&self, write: W) -> EncodingWriter<W> {
        match self {
            Encoding::Hex => EncodingWriter::Hex(HexWriter::new(write)),
            Encoding::Base64 => EncodingWriter::Base64(Base64Writer::new(write, &BASE64_STANDARD)),
            Encoding::Base64url => {
                EncodingWriter::Base64url(Base64Writer::new(write, &BASE64_URL_SAFE))
            }
        }
    }
    pub fn decode_reader<R: Read>(&self, read: R) -> EncodingReader<R> {
        match self {
            Encoding::Hex => EncodingReader::Hex(HexReader::new(read)),
            Encoding::Base64 => EncodingReader::Base64(Base64Reader::new(read, &BASE64_STANDARD)),
            Encoding::Base64url => {
                EncodingReader::Base64url(Base64Reader::new(read, &BASE64_URL_SAFE))
            }
        }
    }

    fn encode_base64(value: &[u8]) -> String {
        BASE64_STANDARD.encode(value)
    }
    fn encode_base64_url(value: &[u8]) -> String {
        BASE64_URL_SAFE.encode(value)
    }
    fn encode_hex(value: &[u8]) -> String {
        hex::encode(value)
    }
    fn decode_base64(value: &[u8]) -> anyhow::Result<Vec<u8>> {
        BASE64_STANDARD
            .decode(value)
            .context("failed to decode base64")
    }
    fn decode_hex(value: &[u8]) -> anyhow::Result<Vec<u8>> {
        hex::decode(value).context("failed to decode hex")
    }
    fn decode_base64_url(value: &[u8]) -> anyhow::Result<Vec<u8>> {
        BASE64_URL_SAFE
            .decode(value)
            .context("failed to decode base64")
    }
}

pub enum EncodingReader<R>
where
    R: Read,
{
    Base64(Base64Reader<'static, GeneralPurpose, R>),
    Base64url(Base64Reader<'static, GeneralPurpose, R>),
    Hex(HexReader<R>),
}
impl<R: Read> Read for EncodingReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        match self {
            EncodingReader::Base64(r) => r.read(buf),
            EncodingReader::Base64url(r) => r.read(buf),
            EncodingReader::Hex(r) => r.read(buf),
        }
    }
}

pub struct HexReader<R: Read>(R);
impl<R: Read> HexReader<R> {
    pub fn new(src: R) -> Self {
        Self(src)
    }
}

pub enum EncodingWriter<W>
where
    W: Write,
{
    Base64(Base64Writer<'static, GeneralPurpose, W>),
    Base64url(Base64Writer<'static, GeneralPurpose, W>),
    Hex(HexWriter<W>),
}
impl<W: Write> Write for EncodingWriter<W> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        match self {
            EncodingWriter::Base64(w) => w.write(buf),
            EncodingWriter::Base64url(w) => w.write(buf),
            EncodingWriter::Hex(w) => w.write(buf),
        }
    }
    fn flush(&mut self) -> std::io::Result<()> {
        match self {
            EncodingWriter::Base64(w) => w.flush(),
            EncodingWriter::Base64url(w) => w.flush(),
            EncodingWriter::Hex(w) => w.flush(),
        }
    }
}

#[allow(unused_must_use)]
impl<W: Write> Drop for EncodingWriter<W> {
    fn drop(&mut self) {
        match self {
            EncodingWriter::Base64(w) => {
                if w.flush().is_ok() {
                    w.finish();
                }
            }
            EncodingWriter::Base64url(w) => {
                if w.flush().is_ok() {
                    w.finish();
                }
            }
            EncodingWriter::Hex(w) => {
                w.flush();
            }
        };
    }
}

impl<R: Read> Read for HexReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let mut data = vec![0; buf.len() * 2];
        let n = self.0.read(&mut data)?;

        hex::decode_to_slice(&data[0..n], &mut buf[0..(n / 2)]).map_err(|e| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("failed to decode hex: {}", e),
            )
        })?;
        Ok(n / 2)
    }
}
pub struct HexWriter<W: Write> {
    w: W,
    buf: VecDeque<u8>,
}
impl<W: Write> HexWriter<W> {
    pub fn new(w: W) -> Self {
        Self {
            w,
            buf: VecDeque::new(),
        }
    }
}
impl<W: Write> Write for HexWriter<W> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.buf.reserve(buf.len() * 2);
        for b in hex::encode(buf).as_bytes() {
            self.buf.push_back(*b);
        }
        let mut i = 0;
        let mut data = vec![0; self.buf.len()];
        while i < buf.len() && !self.buf.is_empty() {
            data[i] = self.buf.pop_front().unwrap();
            i += 1;
        }
        self.w.write(&data[0..i])
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.w.flush()
    }
}

#[allow(unused_must_use)]
impl<W: Write> Drop for HexWriter<W> {
    fn drop(&mut self) {
        self.w.write(self.buf.make_contiguous()); // error is ignored
    }
}

impl FromStr for Encoding {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match &*s
            .chars()
            .filter(|c| !c.is_whitespace() && *c != '-' && *c != '_')
            .flat_map(|c| c.to_lowercase())
            .collect::<String>()
        {
            "base64" => Ok(Self::Base64),
            "base64url" => Ok(Self::Base64url),
            _ => bail!("unknown encoding: {}", s),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::engine::general_purpose::{STANDARD, STANDARD_NO_PAD, URL_SAFE, URL_SAFE_NO_PAD};
    use strum::IntoEnumIterator;
    #[test]
    fn test_encoding() {
        let rng = navajo::rand::SystemRng::default();
        let mut count = 0;
        while count == 0 {
            count = rng.u8().unwrap() % 100;
        }
        for _ in 0..count {
            let mut size = 0;
            while size == 0 {
                size = rng.u8().unwrap() as usize;
            }

            let mut bytes = vec![0; size];
            rng.fill(&mut bytes).unwrap();

            let encoded = Encoding::Base64.encode(&bytes);
            let decoded = STANDARD_NO_PAD.decode(&encoded).unwrap();
            assert_eq!(bytes, decoded.as_slice());

            let encoded = Encoding::Base64.encode(&bytes);
            let decoded = STANDARD_NO_PAD.decode(&encoded).unwrap();
            assert_eq!(bytes, decoded.as_slice());

            let encoded = Encoding::Base64url.encode(&bytes);
            let decoded = URL_SAFE.decode(&encoded).unwrap();
            assert_eq!(bytes, decoded.as_slice());

            let encoded = Encoding::Base64url.encode(&bytes);
            let decoded = URL_SAFE_NO_PAD.decode(&encoded).unwrap();
            assert_eq!(bytes, decoded.as_slice());

            let encoded = Encoding::Hex.encode(&bytes);
            let decoded = hex::decode(&encoded).unwrap();
            assert_eq!(bytes, decoded.as_slice());
        }
    }

    #[test]
    fn test_decoding() {
        let rng = navajo::rand::SystemRng::default();
        let mut count = 0;
        while count == 0 {
            count = rng.u8().unwrap() % 100;
        }
        for _ in 0..count {
            let mut size = 0;
            while size == 0 {
                size = rng.u8().unwrap() as usize;
            }

            let mut bytes = vec![0; size];
            rng.fill(&mut bytes).unwrap();

            let encoded = STANDARD.encode(&bytes);
            let decoded = Encoding::Base64.decode(&encoded).unwrap();
            assert_eq!(bytes, decoded.as_slice());

            let encoded = STANDARD_NO_PAD.encode(&bytes);
            let decoded = Encoding::Base64.decode(&encoded).unwrap();
            assert_eq!(bytes, decoded.as_slice());

            let encoded = URL_SAFE.encode(&bytes);
            let decoded = Encoding::Base64url.decode(&encoded).unwrap();
            assert_eq!(bytes, decoded.as_slice());

            let encoded = URL_SAFE_NO_PAD.encode(&bytes);
            let decoded = Encoding::Base64url.decode(&encoded).unwrap();
            assert_eq!(bytes, decoded.as_slice());

            let encoded = hex::encode(&bytes);
            let decoded = Encoding::Hex.decode(&encoded).unwrap();
            assert_eq!(bytes, decoded.as_slice());
        }
    }
    #[test]
    fn test_decode_reader() {
        let rng = navajo::rand::SystemRng::default();
        let mut count = 0;
        while count == 0 {
            count = rng.u8().unwrap();
        }
        for _ in 0..count {
            let mut size = 0;
            while size == 0 {
                size = rng.u8().unwrap() as usize;
            }
            let mut bytes = vec![0; size];
            rng.fill(&mut bytes).unwrap();

            for encoding in Encoding::iter() {
                let encoded = encoding.encode(&bytes);
                let mut reader = encoding.decode_reader(encoded.as_bytes());
                let mut decoded = vec![];

                reader
                    .read_to_end(&mut decoded)
                    .unwrap_or_else(|_| panic!("encoding: {:?} failed", encoding));

                assert_eq!(bytes, decoded, "encoding: {:?} failed", encoding);
            }
        }
    }
    #[test]
    fn test_encoding_writer() {
        let rng = navajo::rand::SystemRng::default();
        let mut count = 0;
        while count == 0 {
            count = rng.u8().unwrap();
        }
        for _ in 0..count {
            let mut size = 0;
            while size == 0 {
                size = rng.u8().unwrap() as usize;
            }
            let mut bytes = vec![0; size];
            rng.fill(&mut bytes).unwrap();

            for encoding in Encoding::iter() {
                let expected = encoding.encode(&bytes);
                let mut result = vec![];
                let mut w = encoding.encode_writer(&mut result);
                let len = w.write_all(&bytes);
                if let Err(e) = len {
                    panic!("encoding: {:?} failed: {}", encoding, e);
                }
                drop(w);
                len.unwrap();
                assert_eq!(
                    expected,
                    String::from_utf8_lossy(&result),
                    "encoding: {:?} failed",
                    encoding
                );
            }
        }
    }
}
