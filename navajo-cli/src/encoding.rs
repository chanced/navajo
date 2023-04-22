use std::collections::VecDeque;
use std::io::{Read, Write};
use std::mem;
use std::str::FromStr;

use anyhow::{bail, Context, Result};
use base64::engine::{
    general_purpose::{STANDARD as BASE64_STANDARD, URL_SAFE as BASE64_URL_SAFE},
    DecodePaddingMode, GeneralPurpose, GeneralPurposeConfig,
};
use base64::read::DecoderReader as Base64Reader;
use base64::write::EncoderWriter as Base64Writer;
use base64::Engine;
use clap::ValueEnum;

const BASE64_STANDARD_NO_PAD_INDIF: GeneralPurpose = GeneralPurpose::new(
    &base64::alphabet::STANDARD,
    GeneralPurposeConfig::new()
        .with_encode_padding(false)
        .with_decode_padding_mode(DecodePaddingMode::Indifferent),
);
const BASE64_URL_SAFE_NO_PAD_INDIF: GeneralPurpose = GeneralPurpose::new(
    &base64::alphabet::URL_SAFE,
    GeneralPurposeConfig::new()
        .with_encode_padding(false)
        .with_decode_padding_mode(DecodePaddingMode::Indifferent),
);

#[derive(Clone, Copy, PartialEq, Eq, Debug, ValueEnum, strum::Display, strum::EnumIter)]
#[strum(serialize_all = "lowercase")]
/// The encoding of a value, used for determining how to encode or decode a value.
///
/// For Base64 and Base64Url, padding is indifferent for decoding
///
pub enum Encoding {
    /// Base64; decoding is indifferent to padding and defaults to no padding on output unless overridden --out
    Base64,
    /// Base64 URL; decoding is indifferent to padding while padding is optional for encoding
    #[strum(serialize = "base64url")]
    Base64url,
    /// Hex encoding
    Hex,
}

impl Encoding {
    pub fn encode<T>(&self, value: T, pad: bool) -> String
    where
        T: AsRef<[u8]>,
    {
        match self {
            Encoding::Hex => Self::encode_hex(value.as_ref()),
            Encoding::Base64 => Self::encode_base64(value.as_ref(), pad),
            Encoding::Base64url => Self::encode_base64_url(value.as_ref(), pad),
        }
    }

    pub fn decode<T>(&self, value: T) -> Result<Vec<u8>>
    where
        T: AsRef<[u8]>,
    {
        match self {
            Encoding::Hex => Self::decode_hex(value.as_ref()),
            Encoding::Base64 => Self::decode_base64(value.as_ref()),
            Encoding::Base64url => Self::decode_base64_url(value.as_ref()),
        }
    }
    pub fn encode_writer<W: Write>(&self, write: W, pad: bool) -> EncodingWriter<W> {
        match self {
            Encoding::Hex => EncodingWriter::Hex(HexWriter::new(write).into()),
            Encoding::Base64 => {
                if pad {
                    EncodingWriter::Base64(Base64Writer::new(write, &BASE64_STANDARD).into())
                } else {
                    EncodingWriter::Base64(
                        Base64Writer::new(write, &BASE64_STANDARD_NO_PAD_INDIF).into(),
                    )
                }
            }
            Encoding::Base64url => {
                if pad {
                    EncodingWriter::Base64Url(Base64Writer::new(write, &BASE64_URL_SAFE).into())
                } else {
                    EncodingWriter::Base64Url(
                        Base64Writer::new(write, &BASE64_URL_SAFE_NO_PAD_INDIF).into(),
                    )
                }
            }
        }
    }
    pub fn decode_reader<R: Read>(&self, read: R) -> EncodingReader<R> {
        match self {
            Encoding::Hex => EncodingReader::Hex(HexReader::new(read)),
            Encoding::Base64 => {
                EncodingReader::Base64(Base64Reader::new(read, &BASE64_STANDARD_NO_PAD_INDIF))
            }
            Encoding::Base64url => {
                EncodingReader::Base64url(Base64Reader::new(read, &BASE64_URL_SAFE_NO_PAD_INDIF))
            }
        }
    }

    fn encode_base64(value: &[u8], pad: bool) -> String {
        if pad {
            base64::engine::general_purpose::STANDARD.encode(value)
        } else {
            BASE64_STANDARD_NO_PAD_INDIF.encode(value)
        }
    }
    fn encode_base64_url(value: &[u8], pad: bool) -> String {
        if pad {
            base64::engine::general_purpose::URL_SAFE.encode(value)
        } else {
            BASE64_URL_SAFE_NO_PAD_INDIF.encode(value)
        }
    }
    fn encode_hex(value: &[u8]) -> String {
        hex::encode(value)
    }
    fn decode_base64(value: &[u8]) -> Result<Vec<u8>> {
        BASE64_STANDARD_NO_PAD_INDIF
            .decode(value)
            .context("failed to decode base64")
    }
    fn decode_hex(value: &[u8]) -> Result<Vec<u8>> {
        hex::decode(value).context("failed to decode hex")
    }
    fn decode_base64_url(value: &[u8]) -> Result<Vec<u8>> {
        BASE64_URL_SAFE_NO_PAD_INDIF
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
    None(R),
}
impl<R: Read> Read for EncodingReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        match self {
            EncodingReader::Base64(r) => r.read(buf),
            EncodingReader::Base64url(r) => r.read(buf),
            EncodingReader::Hex(r) => r.read(buf),
            EncodingReader::None(r) => r.read(buf),
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
    Base64(Option<Base64Writer<'static, GeneralPurpose, W>>),
    Base64Url(Option<Base64Writer<'static, GeneralPurpose, W>>),
    Base64Padded(Option<Base64Writer<'static, GeneralPurpose, W>>),
    Base64UrlPadded(Option<Base64Writer<'static, GeneralPurpose, W>>),
    Hex(Option<HexWriter<W>>),
    None(Option<W>),
}

impl<W: Write> EncodingWriter<W> {
    pub fn into_inner(mut self) -> Result<W> {
        match self {
            EncodingWriter::Base64(ref mut w) => {
                let mut w = w.take().context("writer already closed")?;
                w.flush()?;
                w.finish()?;
                Ok(w.into_inner())
            }
            EncodingWriter::Base64Url(ref mut w) => {
                let mut w = w.take().context("writer already closed")?;
                w.flush()?;
                w.finish()?;
                Ok(w.into_inner())
            }
            EncodingWriter::Hex(ref mut w) => {
                let mut w = w.take().context("writer already closed")?;
                w.flush()?;
                w.into_inner()
            }
            EncodingWriter::Base64Padded(ref mut w) => {
                let mut w = w.take().context("writer already closed")?;
                w.flush()?;
                w.finish()?;
                Ok(w.into_inner())
            }
            EncodingWriter::Base64UrlPadded(ref mut w) => {
                let mut w = w.take().context("writer already closed")?;
                w.flush()?;
                w.finish()?;
                Ok(w.into_inner())
            }
            EncodingWriter::None(ref mut w) => {
                let w = w.take().context("writer already closed")?;
                Ok(w)
            }
        }
    }
}
impl<W: Write> Write for EncodingWriter<W> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        match self {
            EncodingWriter::Base64(ref mut w) => {
                check_if_closed(w)?;
                w.as_mut().unwrap().write(buf)
            }
            EncodingWriter::Base64Url(ref mut w) => {
                check_if_closed(w)?;
                w.as_mut().unwrap().write(buf)
            }
            EncodingWriter::Hex(ref mut w) => {
                check_if_closed(w)?;
                w.as_mut().unwrap().write(buf)
            }
            EncodingWriter::Base64Padded(ref mut w) => {
                check_if_closed(w)?;
                w.as_mut().unwrap().write(buf)
            }
            EncodingWriter::Base64UrlPadded(ref mut w) => {
                check_if_closed(w)?;
                w.as_mut().unwrap().write(buf)
            }
            EncodingWriter::None(ref mut w) => {
                check_if_closed(w)?;
                w.as_mut().unwrap().write(buf)
            }
        }
    }
    fn flush(&mut self) -> std::io::Result<()> {
        match self {
            EncodingWriter::Base64(w) => {
                w.as_mut().and_then(|w| w.flush().into()).unwrap_or(Ok(()))
            }
            EncodingWriter::Base64Url(w) => {
                w.as_mut().and_then(|w| w.flush().into()).unwrap_or(Ok(()))
            }
            EncodingWriter::Hex(w) => w.as_mut().and_then(|w| w.flush().into()).unwrap_or(Ok(())),
            EncodingWriter::Base64Padded(w) => {
                w.as_mut().and_then(|w| w.flush().into()).unwrap_or(Ok(()))
            }
            EncodingWriter::Base64UrlPadded(w) => {
                w.as_mut().and_then(|w| w.flush().into()).unwrap_or(Ok(()))
            }
            EncodingWriter::None(w) => w.as_mut().and_then(|w| w.flush().into()).unwrap_or(Ok(())),
        }
    }
}

#[allow(unused_must_use)]
impl<W: Write> Drop for EncodingWriter<W> {
    fn drop(&mut self) {
        match self {
            EncodingWriter::Base64(w) => {
                if let Some(w) = w {
                    if w.flush().is_ok() {
                        w.finish();
                    }
                }
            }
            EncodingWriter::Base64Url(w) => {
                if let Some(w) = w {
                    if w.flush().is_ok() {
                        w.finish();
                    }
                }
            }
            EncodingWriter::Hex(w) => {
                if let Some(w) = w {
                    w.flush();
                }
            }
            EncodingWriter::Base64Padded(w) => {
                if let Some(w) = w {
                    if w.flush().is_ok() {
                        w.finish();
                    }
                }
            }
            EncodingWriter::Base64UrlPadded(w) => {
                if let Some(w) = w {
                    if w.flush().is_ok() {
                        w.finish();
                    }
                }
            }
            EncodingWriter::None(w) => {
                if let Some(w) = w {
                    w.flush();
                }
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
    w: Option<W>,
    buf: VecDeque<u8>,
    remnant: Option<u8>,
}
impl<W: Write> HexWriter<W> {
    pub fn new(w: W) -> Self {
        Self {
            w: Some(w),
            buf: VecDeque::new(),
            remnant: None,
        }
    }
    /// Flushes the internal buffer and returns the underlying writer.
    fn into_inner(mut self) -> Result<W, anyhow::Error> {
        self.flush()?;
        self.w
            .take()
            .ok_or(anyhow::anyhow!("writer is already closed"))
    }
}
impl<W: Write> Write for HexWriter<W> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        check_if_closed(&self.w)?;

        let mut remaining = buf.len();
        let mut encoded = Vec::with_capacity(remaining);

        if let Some(remnant) = self.remnant.take() {
            encoded.push(remnant);
            remaining -= 1;
        }
        self.buf.extend(buf.iter());
        while remaining > 0 && !self.buf.is_empty() {
            if remaining > 1 {
                encoded.extend([0, 0].iter());
                let len = encoded.len();
                hex::encode_to_slice([self.buf.pop_front().unwrap()], &mut encoded[len - 2..])
                    .map_err(|e| {
                        std::io::Error::new(
                            std::io::ErrorKind::InvalidData,
                            format!("failed to encode hex: {}", e),
                        )
                    })?;
                remaining -= 2;
            } else {
                let mut last_bytes = [0u8, 0u8];
                hex::encode_to_slice([self.buf.pop_front().unwrap()], &mut last_bytes).map_err(
                    |e| {
                        std::io::Error::new(
                            std::io::ErrorKind::InvalidData,
                            format!("failed to encode hex: {}", e),
                        )
                    },
                )?;
                encoded.push(last_bytes[0]);
                self.remnant = Some(last_bytes[1]);
                break;
            }
        }
        self.w.as_mut().unwrap().write(&encoded)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        if self.w.is_none() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                "writer is already closed",
            ));
        }
        let mut remaining = vec![0u8; self.buf.len() * 2];
        let mut start = 0;
        if let Some(remnant) = self.remnant.take() {
            remaining.push(0);
            remaining[0] = remnant;
            start = 1;
        }
        let mut buf = mem::take(&mut self.buf);
        hex::encode_to_slice(buf.make_contiguous(), &mut remaining[start..]).map_err(|e| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("failed to encode hex: {}", e),
            )
        })?;
        let w = self.w.as_mut().unwrap();
        w.write_all(&remaining)?;
        w.flush()
    }
}

#[allow(unused_must_use)]
impl<W: Write> Drop for HexWriter<W> {
    fn drop(&mut self) {
        let w = self.w.take();
        if let Some(mut w) = w {
            w.write_all(self.buf.make_contiguous()); // error is ignored
        }
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

fn check_if_closed<T>(w: &Option<T>) -> Result<(), std::io::Error> {
    if w.is_none() {
        Err(std::io::Error::new(
            std::io::ErrorKind::Other,
            "writer already closed",
        ))
    } else {
        Ok(())
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

            let encoded = Encoding::Base64.encode(&bytes, false);
            let decoded = STANDARD_NO_PAD.decode(&encoded).unwrap();
            assert_eq!(bytes, decoded.as_slice());

            let encoded = Encoding::Base64.encode(&bytes, false);
            let decoded = STANDARD_NO_PAD.decode(&encoded).unwrap();
            assert_eq!(bytes, decoded.as_slice());

            let encoded = Encoding::Base64url.encode(&bytes, false);
            let decoded = URL_SAFE_NO_PAD.decode(&encoded).unwrap();
            assert_eq!(bytes, decoded.as_slice());

            let encoded = Encoding::Base64url.encode(&bytes, false);
            let decoded = URL_SAFE_NO_PAD.decode(&encoded).unwrap();
            assert_eq!(bytes, decoded.as_slice());

            let encoded = Encoding::Hex.encode(&bytes, false);
            let decoded = hex::decode(&encoded).unwrap();
            assert_eq!(bytes, decoded.as_slice());

            let encoded = Encoding::Base64.encode(&bytes, true);
            let decoded = STANDARD.decode(&encoded).unwrap();
            assert_eq!(bytes, decoded.as_slice());

            let encoded = Encoding::Base64.encode(&bytes, true);
            let decoded = STANDARD.decode(&encoded).unwrap();
            assert_eq!(bytes, decoded.as_slice());

            let encoded = Encoding::Base64url.encode(&bytes, true);
            let decoded = URL_SAFE.decode(&encoded).unwrap();
            assert_eq!(bytes, decoded.as_slice());

            let encoded = Encoding::Base64url.encode(&bytes, true);
            let decoded = URL_SAFE.decode(&encoded).unwrap();
            assert_eq!(bytes, decoded.as_slice());

            let encoded = Encoding::Hex.encode(&bytes, true);
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
                let encoded = encoding.encode(&bytes, false);
                let mut reader = encoding.decode_reader(encoded.as_bytes());
                let mut decoded = vec![];

                reader
                    .read_to_end(&mut decoded)
                    .unwrap_or_else(|_| panic!("encoding: {:?} failed", encoding));

                assert_eq!(bytes, decoded, "encoding: {:?} failed", encoding);

                let encoded = encoding.encode(&bytes, true);
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
            count = rng.u8().unwrap() % 10;
        }
        for _ in 0..count {
            let mut size = 0;
            while size == 0 {
                size = rng.u8().unwrap() as usize;
            }
            let mut bytes = vec![0; size];
            rng.fill(&mut bytes).unwrap();

            for encoding in Encoding::iter() {
                let expected = encoding.encode(&bytes, false);
                let mut result = vec![];
                let mut w = encoding.encode_writer(&mut result, false);
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

                let expected = encoding.encode(&bytes, true);
                let mut result = vec![];
                let mut w = encoding.encode_writer(&mut result, true);
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
