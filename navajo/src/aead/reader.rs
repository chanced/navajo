use core::marker::PhantomData;
use std::io::Read;

use alloc::collections::VecDeque;

use crate::{error::DecryptError, Aead};

use super::Decryptor;

pub struct DecryptReader<R, D, K>
where
    R: Read,
    D: AsRef<[u8]>,
    K: AsRef<Aead>,
{
    reader: R,
    _marker: PhantomData<K>,
    aad: D,
    deserializer: Option<Decryptor<K, Vec<u8>>>,
    buffer: VecDeque<u8>,
}
impl<R, D, K> DecryptReader<R, D, K>
where
    R: Read,
    D: AsRef<[u8]>,
    K: AsRef<Aead>,
{
    pub fn new(reader: R, additional_data: D, key: K) -> Self {
        Self {
            reader,
            _marker: PhantomData,
            aad: additional_data,
            deserializer: Some(Decryptor::new(key, Vec::new())),
            buffer: VecDeque::new(),
        }
    }
    fn update(&mut self, mut ctr: usize, iter: impl Iterator<Item = u8>, buf: &mut [u8]) -> usize {
        for b in iter {
            if ctr < buf.len() {
                buf[ctr] = b;
                ctr += 1;
            } else {
                self.buffer.push_back(b);
            }
        }
        ctr
    }
}
impl<R, D, K> Read for DecryptReader<R, D, K>
where
    R: Read,
    K: AsRef<Aead>,
    D: AsRef<[u8]>,
{
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let mut ctr = 0;

        if !self.buffer.is_empty() {
            for i in 0..self.buffer.len() {
                if buf.len() == i {
                    break;
                }
                buf[i] = self.buffer.pop_front().unwrap();
                ctr = i + 1;
            }
        }
        if ctr == buf.len() {
            return Ok(ctr);
        }

        if self.deserializer.is_none() {
            return Ok(ctr);
        }
        let mut deserializer = self.deserializer.take().unwrap();
        let mut offset = 0;
        if deserializer.method().is_none() {
            let mut method_byte = [0u8; 1];
            let n = self.reader.read(&mut method_byte)?;
            if n == 0 {
                return Ok(ctr);
            }
            deserializer.update(self.aad.as_ref(), &method_byte)?;
            offset = 1;
        }

        if deserializer.method().is_none() {
            return Err(DecryptError::Unspecified.into());
        }
        match deserializer.method().unwrap() {
            crate::aead::Method::Online => {
                let mut data: Vec<u8> = Vec::new();
                self.reader.read_to_end(&mut data)?;
                let result = deserializer.finalize(self.aad.as_ref())?;
                Ok(self.update(ctr, result.flatten(), buf))
            }
            crate::aead::Method::StreamingHmacSha256(segment) => {
                let mut data: Vec<u8> = vec![0u8; segment - offset];
                let n = self.reader.read(&mut data)?;
                deserializer.update(self.aad.as_ref(), &data[..n])?;
                if n < segment - offset {
                    let result = self.update(
                        ctr,
                        deserializer.finalize(self.aad.as_ref())?.flatten(),
                        buf,
                    );
                    Ok(result)
                } else {
                    let result = self.update(
                        ctr,
                        deserializer
                            .next(self.aad.as_ref())?
                            .unwrap()
                            .iter()
                            .cloned(),
                        buf,
                    );
                    self.deserializer = Some(deserializer);
                    Ok(result)
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::aead::{Algorithm, Encryptor, Segment};

    use super::*;

    #[test]
    fn test_read() {
        let mut data = vec![0u8; 6024];
        crate::rand::fill(&mut data);
        let aead = Aead::new(Algorithm::ChaCha20Poly1305, None);
        let mut encryptor = Encryptor::new(&aead, Some(Segment::FourKilobytes), Vec::new());
        encryptor.update(&[], &data).unwrap();
        let ciphertext = encryptor
            .finalize(&[])
            .unwrap()
            .flatten()
            .collect::<Vec<u8>>();
        let mut reader = DecryptReader::new(&ciphertext[..], &[], &aead);
        let mut buf = Vec::new();
        reader.read_to_end(&mut buf).unwrap();
        assert_eq!(data.len(), buf.len());
    }
}
