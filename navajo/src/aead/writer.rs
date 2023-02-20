use std::io::Write;

use alloc::collections::VecDeque;

use crate::Aead;

use super::{Buffer, Encryptor, Segment};

/// Implements [`std::io::Write`] for encrypting data. This type is used
/// internally by [`Aead`] for the method
/// [`encrypt_writer`](`Aead::encrypt_writer`).
///
/// If used outside independently of [`Aead::encrypt_writer`], then the
/// [`finalize`](`Self::finalize`) **must** be called or the ciphertext will be
/// incomplete. [`Aead::encrypt_writer`] handles the finalization.
#[cfg(feature = "std")]
pub struct EncryptWriter<W, D>
where
    W: Write,
    D: AsRef<[u8]>,
{
    encryptor: Encryptor<Vec<u8>>,
    writer: W,
    aad: D,
    buffer: VecDeque<u8>,
}
impl<W, D> EncryptWriter<W, D>
where
    W: Write,
    D: AsRef<[u8]>,
{
    pub fn new(writer: W, segment: Segment, additional_data: D, aead: impl AsRef<Aead>) -> Self {
        let encryptor = Encryptor::new(
            aead.as_ref(),
            Some(segment),
            Vec::with_capacity(segment.into()),
        );
        Self {
            encryptor,
            writer,
            aad: additional_data,
            buffer: VecDeque::with_capacity(segment.into()),
        }
    }
}
impl<W, D> EncryptWriter<W, D>
where
    W: Write,
    D: AsRef<[u8]>,
{
    pub fn finalize(mut self) -> Result<W, std::io::Error> {
        self.encryptor.finalize(self.aad.as_ref())?;
        Ok(self.writer)
    }
}
impl<W, D> Write for EncryptWriter<W, D>
where
    W: Write,
    D: AsRef<[u8]>,
{
    fn write(&mut self, buf: &[u8]) -> Result<usize, std::io::Error> {
        todo!()
        // self.encryptor.update(self.aad.as_ref(), buf)?;
        // if let Some(buf) = self.encryptor.next() {
        //     self.writer.write_all(&buf)?;
        // }
        // let r = self.encryptor.next().map(|buf| {
        //     self.writer.write_all(&buf)?;
        //     Ok(buf.len())
        // });
        // self.writer.write(buf)
    }

    fn flush(&mut self) -> Result<(), std::io::Error> {
        self.writer.flush()
    }
}
