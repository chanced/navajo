use core::marker::PhantomData;
use std::io::Read;

use alloc::collections::VecDeque;

use crate::{error::DecryptError, rand::Random, Aad, Aead, SystemRandom};

use super::Decryptor;

pub struct DecryptReader<R, A, K, Rand = SystemRandom>
where
    R: Read,
    A: AsRef<[u8]>,
    K: AsRef<Aead>,
    Rand: Random,
{
    reader: R,
    _marker: PhantomData<K>,
    aad: Aad<A>,
    deserializer: Option<Decryptor<K, Vec<u8>, Rand>>,
    buffer: VecDeque<u8>,
    rand: Rand,
}
impl<R, A, K> DecryptReader<R, A, K, SystemRandom>
where
    R: Read,
    A: AsRef<[u8]>,
    K: AsRef<Aead>,
{
    pub fn new(reader: R, aad: Aad<A>, key: K) -> Self {
        Self {
            reader,
            _marker: PhantomData,
            aad,
            deserializer: Some(Decryptor::new(key, Vec::new())),
            buffer: VecDeque::new(),
            rand: SystemRandom,
        }
    }
}

impl<R, A, K, Rand> DecryptReader<R, A, K, Rand>
where
    R: Read,
    A: AsRef<[u8]>,
    K: AsRef<Aead>,
    Rand: Random,
{
    #[cfg(test)]
    pub fn new_with_rand(rand: Rand, reader: R, aad: Aad<A>, key: K) -> Self {
        Self {
            reader,
            _marker: PhantomData,
            aad,
            deserializer: Some(Decryptor::new_with_rand(rand.clone(), key, Vec::new())),
            buffer: VecDeque::new(),
            rand,
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
            deserializer.update(Aad(self.aad.as_ref()), &method_byte)?;
            offset = 1;
        }

        if deserializer.method().is_none() {
            return Err(DecryptError::Unspecified.into());
        }
        match deserializer.method().unwrap() {
            crate::aead::Method::Online => {
                let mut data: Vec<u8> = Vec::new();
                self.reader.read_to_end(&mut data)?;
                let result = deserializer.finalize(Aad(self.aad.as_ref()))?;
                Ok(self.update(ctr, result.flatten(), buf))
            }
            crate::aead::Method::StreamingHmacSha256(segment) => {
                let mut data: Vec<u8> = vec![0u8; segment - offset];
                let n = self.reader.read(&mut data)?;
                deserializer.update(Aad(self.aad.as_ref()), &data[..n])?;
                if n < segment - offset {
                    let result = self.update(
                        ctr,
                        deserializer.finalize(Aad(self.aad.as_ref()))?.flatten(),
                        buf,
                    );
                    Ok(result)
                } else {
                    let result = self.update(
                        ctr,
                        deserializer
                            .next(Aad(self.aad.as_ref()))?
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
    use crate::{
        aead::{Algorithm, Encryptor, Segment},
        SystemRandom,
    };

    use super::*;

    #[test]
    fn test_read() {
        let mut data = vec![0u8; 6024];
        let rand = SystemRandom::new();
        rand.fill(&mut data);
        let aead = Aead::new(Algorithm::ChaCha20Poly1305, None);
        let mut encryptor = Encryptor::new(&aead, Some(Segment::FourKilobytes), Vec::new());
        encryptor.update(Aad::empty(), &data).unwrap();
        let ciphertext = encryptor
            .finalize(Aad::empty())
            .unwrap()
            .flatten()
            .collect::<Vec<u8>>();
        let mut reader = DecryptReader::new(&ciphertext[..], Aad::empty(), &aead);
        let mut buf = Vec::new();
        reader.read_to_end(&mut buf).unwrap();
        assert_eq!(data.len(), buf.len());
    }
}
