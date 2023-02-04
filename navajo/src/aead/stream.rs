use std::{
    collections::VecDeque,
    marker::PhantomData,
    mem,
    ops::Deref,
    sync::Arc,
    task::Poll::{self, Pending, Ready},
};

use crate::{Aead, DecryptStreamError, EncryptError, EncryptStreamError, KEY_ID_LEN};

use super::{
    header::Header,
    nonce::{Nonce, NonceSequence},
    salt::Salt,
    Key, Method, Segment,
};
use futures::{stream::FusedStream, Stream, TryStream};
use pin_project::pin_project;
use ring::hkdf;
use zeroize::Zeroize;

pub trait EncryptStream: TryStream {
    fn encrypt<A, K>(
        self,
        segment_size: Segment,
        additional_data: A,
        aead: &Aead,
    ) -> Result<Encrypt<Self, Self::Ok, Self::Error>, EncryptError>
    where
        K: AsRef<Aead>,
        Self: Sized,
        Self::Ok: AsRef<[u8]>,
        Self::Error: std::error::Error,
        A: AsRef<[u8]>,
    {
        Encrypt::new(self, segment_size, additional_data, aead)
    }
}

#[pin_project]
pub struct Encrypt<S, T, E>
where
    S: TryStream<Ok = T, Error = E>,
    T: AsRef<[u8]>,
    E: std::error::Error,
{
    #[pin]
    stream: S,
    inner: StreamEncryptor<E>,
    _phantom: PhantomData<E>,
}

pub(super) struct StreamEncryptor<E> {
    pub(super) aad: Vec<u8>,
    pub(super) segment_size: Segment,
    pub(super) key: Arc<Key>,
    pub(super) salt: Option<Salt>,
    pub(super) queue: VecDeque<Vec<u8>>,
    pub(super) buffer: Vec<u8>,
    pub(super) nonce_seq: NonceSequence,
    pub(super) is_done: bool,
    pub(super) _e: PhantomData<E>,
}

impl<S, T, E> Encrypt<S, T, E>
where
    S: TryStream<Ok = T, Error = E>,
    T: AsRef<[u8]>,
    E: std::error::Error,
{
    fn new<A>(
        stream: S,
        segment_size: Segment,
        additional_data: A,
        aead: &Aead,
    ) -> Result<Self, EncryptError>
    where
        A: AsRef<[u8]>,
    {
        let aad = Vec::from(additional_data.as_ref()); // <-- todo: revisit this
        let key = aead.primary()?.derive_key(&aad)?;
        let mut salt_data = vec![0; key.algorithm.key_len()];
        crate::rand::fill(&mut salt_data)?;
        let salt = Salt::new(hkdf::HKDF_SHA256, salt_data); // <-- todo, this may need to be updated to allow for dynamically setting it.
        let algorithm = key.algorithm;
        Ok(Self {
            stream,
            inner: StreamEncryptor {
                aad,
                segment_size,
                key,
                salt: Some(salt),
                is_done: false,
                nonce_seq: NonceSequence::new(algorithm)?,
                buffer: Vec::new(),
                queue: VecDeque::new(),
                _e: PhantomData,
            },
            _phantom: PhantomData,
        })
    }
}
impl<S, T, E> Stream for Encrypt<S, T, E>
where
    S: TryStream<Ok = T, Error = E>,
    T: AsRef<[u8]>,
    E: std::error::Error,
{
    type Item = Result<Vec<u8>, EncryptStreamError<E>>;

    fn poll_next(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> Poll<Option<Self::Item>> {
        let mut this = self.project();
        let inner = this.inner;
        if inner.is_done {
            return Ready(inner.next().map(Ok));
        }
        if let Some(first) = inner.next() {
            return Ready(Some(Ok(first)));
        }
        loop {
            match this.stream.as_mut().try_poll_next(cx) {
                Ready(item) => match item {
                    Some(result) => match result {
                        Ok(result) => match inner.process(Some(result.as_ref())) {
                            Ok(ciphertext) => match ciphertext {
                                Some(ciphertext) => return Ready(Some(Ok(ciphertext))),
                                None => continue,
                            },
                            Err(e) => return Ready(Some(inner.err(e))),
                        },
                        Err(e) => return Ready(Some(inner.err(EncryptStreamError::Upstream(e)))),
                    },
                    None => {
                        inner.process(None)?;
                        inner.is_done = true;
                        return Ready(inner.next().map(Ok));
                    }
                },

                Pending => return Pending,
            }
        }
    }
}
impl<S, T, E> FusedStream for Encrypt<S, T, E>
where
    S: TryStream<Ok = T, Error = E>,
    T: AsRef<[u8]>,
    E: std::error::Error,
{
    fn is_terminated(&self) -> bool {
        self.inner.is_done
    }
}
impl<E> StreamEncryptor<E> {
    pub(super) fn counter(&self) -> u32 {
        self.nonce_seq.counter()
    }
    pub(super) fn next(&mut self) -> Option<Vec<u8>> {
        self.queue.pop_front()
    }
    pub(super) fn err(
        &mut self,
        e: EncryptStreamError<E>,
    ) -> Result<Vec<u8>, EncryptStreamError<E>> {
        self.is_done = true;
        self.queue.clear();
        self.buffer.zeroize();
        Err(e)
    }
    pub(super) fn process(
        &mut self,
        cleartext: Option<&[u8]>,
    ) -> Result<Option<Vec<u8>>, EncryptStreamError<E>> {
        let is_final = if let Some(cleartext) = cleartext {
            self.buffer.extend_from_slice(cleartext);
            false
        } else {
            true
        };

        loop {
            if self.buffer.is_empty() {
                return Ok(None);
            }
            if self.buffer.len() <= self.block_size() {
                if is_final {
                    let segment = self.encrypt_segment(true)?;
                    self.queue.push_back(segment);
                    return Ok(self.queue.pop_front());
                }
                return Ok(None);
            }

            let segment = self.encrypt_segment(false)?;
            self.queue.push_back(segment);
        }
    }
    pub(super) fn block_size(&self) -> usize {
        if self.counter() == 0 {
            return self.segment_size.to_usize()
                - Method::StreamHmacSha256(self.segment_size).header_len(self.key.algorithm);
        }
        self.segment_size.to_usize()
    }

    pub(super) fn encrypt_segment(
        &mut self,
        is_final: bool,
    ) -> Result<Vec<u8>, EncryptStreamError<E>> {
        let mut buf = if !is_final {
            let buf = self.buffer.split_off(self.buffer.len() - self.block_size());
            mem::replace(&mut self.buffer, buf)
        } else {
            self.buffer.split_off(0)
        };
        let (idx, nonce) = self.nonce_seq.advance(is_final)?;
        self.key.encrypt_segment(&mut buf, &self.aad, &nonce)?;

        if idx == 0 {
            let header = Header {
                method: Method::StreamHmacSha256(self.segment_size),
                key_id: self.key.id,
                nonce: nonce.prefix(),
                salt: Some(self.salt.take().unwrap()),
            };
            let mut buf_with_header = Vec::with_capacity(header.len() + buf.len());
            header.write(&mut buf_with_header);
            buf_with_header.extend_from_slice(&buf);
            buf = buf_with_header;
        }
        Ok(buf)
    }
}

pub trait DecryptStream: TryStream {
    fn decrypt<A, K>(self, additional_data: A, aead: K) -> Decrypt<Self, Self::Ok, Self::Error, K>
    where
        Self: Sized,
        Self::Ok: AsRef<[u8]>,
        Self::Error: std::error::Error,
        A: AsRef<[u8]>,
        K: Deref<Target = Aead> + Send + Sync,
    {
        Decrypt::new(self, additional_data, aead)
    }
}

#[pin_project]
pub struct Decrypt<S, T, E, K>
where
    S: TryStream<Ok = T, Error = E>,
    T: AsRef<[u8]>,
    E: std::error::Error,
    K: Deref<Target = Aead> + Send + Sync,
{
    #[pin]
    stream: S,
    inner: StreamDecryptor<K, E>,
    _phantom: PhantomData<E>,
}
impl<S, T, E, K> Decrypt<S, T, E, K>
where
    S: TryStream<Ok = T, Error = E>,
    T: AsRef<[u8]>,
    E: std::error::Error,
    K: Deref<Target = Aead> + Send + Sync,
{
    pub fn new(stream: S, additional_data: impl AsRef<[u8]>, aead: K) -> Self {
        Self {
            stream,
            inner: StreamDecryptor::new(additional_data, aead),
            _phantom: PhantomData,
        }
    }
}
impl<S, T, E, K> Stream for Decrypt<S, T, E, K>
where
    S: TryStream<Ok = T, Error = E>,
    T: AsRef<[u8]>,
    E: std::error::Error,
    K: Deref<Target = Aead> + Send + Sync,
{
    type Item = Result<Vec<u8>, DecryptStreamError<E>>;
    fn poll_next(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> Poll<Option<Self::Item>> {
        let mut this = self.project();
        let mut inner = this.inner;
        if inner.is_done {
            return Ready(None);
        }
        loop {
            match this.stream.as_mut().try_poll_next(cx) {
                Ready(item) => match item {
                    Some(result) => match result {
                        Ok(data) => match inner.process(Some(data.as_ref())) {
                            Ok(processed) => match processed {
                                Some(cleartext) => return Ready(Some(Ok(cleartext))),
                                None => continue,
                            },
                            Err(e) => return Ready(Some(Err(e))),
                        },
                        Err(_) => todo!(),
                    },
                    None => todo!(),
                },
                Pending => todo!(),
            }
        }
    }
}

#[derive(Debug)]
enum DecryptNonce {
    Sequence(NonceSequence),
    Nonce(Nonce),
}

pub(super) struct StreamDecryptor<K, E> {
    keyring: Option<K>,
    method: Option<Method>,
    key: Option<Arc<Key>>,
    salt_parsed: bool,
    buffer: Vec<u8>,
    pending: Option<Vec<u8>>,
    _phantom: PhantomData<E>,
    nonce: Option<DecryptNonce>,
    aad: Vec<u8>,
    is_done: bool,
}

impl<K, E> StreamDecryptor<K, E>
where
    K: Deref<Target = Aead> + Send + Sync,
    E: std::error::Error,
{
    fn new(additional_data: impl AsRef<[u8]>, aead: K) -> Self {
        Self {
            keyring: Some(aead),
            method: None,
            key: None,
            nonce: None,
            salt_parsed: false,
            buffer: Vec::new(),
            pending: None,
            _phantom: PhantomData,
            aad: Vec::from(additional_data.as_ref()),
            is_done: false,
        }
    }

    pub(super) fn process(
        &mut self,
        data: Option<&[u8]>,
    ) -> Result<Option<Vec<u8>>, DecryptStreamError<E>> {
        let is_final = if let Some(data) = data {
            self.buffer.extend_from_slice(data);
            false
        } else {
            true
        };
        if !self.header_is_complete() && !self.parse_header()? {
            return Ok(None);
        }
        if self.has_buffered_segment() {
            let mut segment = self.buffer.split_off(self.segment_size().unwrap());
            mem::swap(&mut self.buffer, &mut segment);

            let cleartext = self.key.as_ref().unwrap().decrypt(segment, &self.aad)?;
            if self.buffer.is_empty() && is_final {
                self.is_done = true;
            }
            Ok(Some(cleartext))
        } else {
            Ok(None)
        }
    }
    pub(super) fn has_buffered_segment(&self) -> bool {
        if !self.header_is_complete() {
            return false;
        }
        self.segment_size()
            .map_or(false, |segment_size| match self.counter() {
                0 => {
                    let key = self.key.as_ref().unwrap();
                    let method = self.method.unwrap();
                    let header_len = method.header_len(key.algorithm);
                    self.buffer.len() > (segment_size - header_len)
                }
                _ => self.buffer.len() > segment_size,
            })
    }
    pub(super) fn err(
        &mut self,
        e: DecryptStreamError<E>,
    ) -> Result<Option<Vec<u8>>, DecryptStreamError<E>> {
        self.is_done = true;
        self.buffer.zeroize();
        Err(e)
    }
    pub(super) fn parse_header(&mut self) -> Result<bool, DecryptStreamError<E>> {
        if self.header_is_complete() {
            return Ok(true);
        }
        if self.buffer.is_empty() {
            return Ok(false);
        }

        if self.method.is_none() {
            let mut method = self.buffer.split_off(1);
            mem::swap(&mut self.buffer, &mut method);
            let method: Method = method[0]
                .try_into()
                .map_err(DecryptStreamError::Malformed)?;
            self.method = Some(method);
        }

        if self.key.is_none() {
            if self.buffer.len() >= KEY_ID_LEN {
                let mut key_id = self.buffer.split_off(KEY_ID_LEN);
                mem::swap(&mut self.buffer, &mut key_id);
                let key_id = u32::from_be_bytes(key_id.try_into().unwrap()); // safe, len is checked above.
                let keyring = self.keyring.take().unwrap(); // safe because key is set or an error ends the stream
                let k = keyring
                    .key(key_id)
                    .ok_or_else(|| DecryptStreamError::KeyNotFound(key_id))?;
                self.key = Some(k);
            } else {
                return Ok(false);
            }
        }
        if self.nonce.is_none() {
            let method = self.method.unwrap();
            let key = self.key.clone().unwrap();
            let algorithm = key.algorithm;
            let nonce_len = match method {
                Method::Online => algorithm.nonce_len(),
                Method::StreamHmacSha256(_) => algorithm.nonce_prefix_len(),
            };
            if self.buffer.len() >= nonce_len {
                let buf = self.buffer.split_off(nonce_len);
                let nonce_bytes = mem::replace(&mut self.buffer, buf);
                let nonce = match method {
                    Method::Online => DecryptNonce::Nonce(Nonce(nonce_bytes.into())),
                    Method::StreamHmacSha256(_) => {
                        let seq = NonceSequence::from(nonce_bytes);
                        DecryptNonce::Sequence(seq)
                    }
                };
                self.nonce = Some(nonce);
            } else {
                return Ok(false);
            }
        }
        if self.should_parse_salt() {
            let key = self.key.clone().unwrap(); // safe; key is set above or an error ends the stream;
            if self.buffer.len() >= key.algorithm.key_len() {
                let buf = self.buffer.split_off(key.algorithm.key_len());
                let salt_bytes = mem::replace(&mut self.buffer, buf);
                let key = key.derive_key_from_salt(&salt_bytes, &self.aad)?;
                self.key = Some(key);
            } else {
                return Ok(false);
            }
        }
        Ok(true)
    }
    pub(super) fn header_is_complete(&self) -> bool {
        if self.method.is_none() {
            return false;
        }
        if self.key.is_none() {
            return false;
        }
        if self.nonce.is_none() {
            return false;
        }
        if self.method.unwrap().is_stream() {
            return self.salt_parsed;
        }
        true
    }
    fn should_parse_salt(&self) -> bool {
        self.method.unwrap().is_stream() && !self.salt_parsed // safe, method is set previously
    }

    pub(super) fn counter(&self) -> u32 {
        self.method.map_or(0, |method| match method {
            Method::Online => 0,
            Method::StreamHmacSha256(seg) => self.nonce.as_ref().map_or(0, |nonce| match nonce {
                DecryptNonce::Nonce(_) => 0,
                DecryptNonce::Sequence(seq) => seq.counter(),
            }),
        })
    }
    pub(super) fn segment_size(&self) -> Option<usize> {
        if let Some(method) = self.method {
            match method {
                Method::Online => None,
                Method::StreamHmacSha256(segment) => Some(segment.to_usize()),
            }
        } else {
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use std::ops::Deref;

    fn x<A>(a: A)
    where
        A: Deref<Target = String> + Send + Sync,
    {
        let x = a.deref();
        println!("{}", x);
    }
    #[tokio::test]
    async fn spike() {}
}
