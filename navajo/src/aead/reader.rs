use std::io::Read;

use crate::Aead;

use super::Decryptor;

pub struct DecryptReader<R, A, K>
where
    R: Read,
    A: AsRef<[u8]>,
    K: AsRef<Aead>,
{
    reader: R,
    aead: K,
    aad: A,
    de: Decryptor<K, Vec<u8>>,
    buffer: Vec<u8>,
}

impl<R, A, K> Read for DecryptReader<R, A, K>
where
    R: Read,
    K: AsRef<Aead>,
    A: AsRef<[u8]>,
{
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        if self.buffer.len() > buf.len() {
            let mut local_buf = self.buffer.split_off(buf.len());
            core::mem::swap(&mut local_buf, &mut self.buffer);
            for (i, b) in local_buf.iter().enumerate() {
                buf[i] = *b;
            }
            return Ok(buf.len());
        }
        if self.de.method().is_none() {
            let mut buf = [0u8; 5];
            let n = self.reader.read(&mut buf)?;
            if n == 0 {
                return Ok(0);
            }
            _ = self.de.parse_header(self.aad.as_ref());
            // self.de.update(self.aad.as_ref(), &buf[..n])?;
        }
        todo!();
    }
}
