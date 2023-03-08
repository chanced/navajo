use std::io::Write;



use crate::{Aad, Aead};

use super::{Buffer, Encryptor, Segment};

/// Implements [`std::io::Write`] for encrypting data. This type is used
/// internally by [`Aead`] for the method
/// [`encrypt_writer`](`Aead::encrypt_writer`).
///
/// If used outside independently of [`Aead::encrypt_writer`], then the
/// [`finalize`](`Self::finalize`) **must** be called or the ciphertext will be
/// incomplete. [`Aead::encrypt_writer`] handles the finalization.
#[cfg(feature = "std")]
pub struct EncryptWriter<'write, W, A>
where
    W: Write,
    A: AsRef<[u8]>,
{
    encryptor: Encryptor<Vec<u8>>,
    writer: &'write mut W,
    aad: Aad<A>,
    counter: usize,
}
impl<'write, W, A> EncryptWriter<'write, W, A>
where
    W: Write,
    A: AsRef<[u8]>,
{
    pub fn new<C>(writer: &'write mut W, segment: Segment, aad: Aad<A>, cipher: C) -> Self
    where
        C: AsRef<Aead>,
    {
        let encryptor = Encryptor::new(cipher, Some(segment), Vec::with_capacity(segment.into()));
        Self {
            encryptor,
            writer,
            aad,
            counter: 0,
        }
    }
}
impl<'write, W, D> EncryptWriter<'write, W, D>
where
    W: Write,
    D: AsRef<[u8]>,
{
    pub fn finalize(self) -> Result<usize, std::io::Error> {
        let EncryptWriter {
            encryptor,
            writer,
            mut counter,
            aad,
        } = self;
        let ciphertext: Vec<u8> = encryptor.finalize(aad)?.flatten().collect();
        writer.write_all(&ciphertext)?;
        counter += ciphertext.len();
        writer.flush()?;
        Ok(counter)
    }
}
impl<'write, W, D> Write for EncryptWriter<'write, W, D>
where
    W: Write,
    D: AsRef<[u8]>,
{
    fn write(&mut self, buf: &[u8]) -> Result<usize, std::io::Error> {
        self.encryptor.update(Aad(self.aad.as_ref()), buf)?;
        if let Some(ciphertext) = self.encryptor.next() {
            self.writer.write_all(&ciphertext)?;
            self.counter += ciphertext.len();
        }
        Ok(buf.len())
    }

    fn flush(&mut self) -> Result<(), std::io::Error> {
        self.writer.flush()
    }
}
