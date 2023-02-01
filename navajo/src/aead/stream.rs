use std::{collections::VecDeque, marker::PhantomData, mem, sync::Arc, task::Poll};

use crate::{Aead, DecryptStreamError, EncryptError, EncryptStreamError};

use super::{
    header::{Header, HeaderWriter},
    nonce::NonceSequence,
    salt::Salt,
    Key, Method, Segment,
};
use bytes::{BufMut, Bytes, BytesMut};
use futures::{stream::FusedStream, Stream, TryStream, TryStreamExt};
use pin_project::pin_project;
use ring::hkdf;
use zeroize::Zeroize;

pub trait EncryptStream: TryStream {
    fn encrypt<A>(
        self,
        segment_size: Segment,
        additional_data: A,
        aead: &Aead,
    ) -> Result<Encrypt<Self, Self::Ok, Self::Error>, EncryptError>
    where
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
    pub(super) aad: Bytes,
    pub(super) segment_size: Segment,
    pub(super) key: Arc<Key>,
    pub(super) salt: Option<Salt>,
    pub(super) queue: VecDeque<Bytes>,
    pub(super) buffer: BytesMut,
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
        let aad = Bytes::from(additional_data.as_ref().to_owned()); // <-- todo: revisit this
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
                buffer: BytesMut::new(),
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
    type Item = Result<Bytes, EncryptStreamError<E>>;

    fn poll_next(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> Poll<Option<Self::Item>> {
        let mut this = self.project();
        let inner = this.inner;
        if inner.is_done {
            return Poll::Ready(inner.next().map(Ok));
        }
        if let Some(first) = inner.next() {
            return Poll::Ready(Some(Ok(first)));
        }
        loop {
            match this.stream.as_mut().try_poll_next(cx) {
                Poll::Ready(Some(Ok(data))) => match inner.process(Some(data.as_ref()), false) {
                    Ok(Some(next)) => return Poll::Ready(Some(Ok(next))),
                    Ok(None) => continue,
                    Err(e) => return Poll::Ready(Some(inner.err(e))),
                },
                Poll::Ready(Some(Err(e))) => {
                    return Poll::Ready(Some(inner.err(EncryptStreamError::Upstream(e))));
                }
                Poll::Ready(None) => {
                    inner.process(None, true)?;
                    inner.is_done = true;
                    return Poll::Ready(inner.next().map(Ok));
                }
                Poll::Pending => return Poll::Pending,
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
    pub(super) fn next(&mut self) -> Option<Bytes> {
        self.queue.pop_front()
    }
    pub(super) fn err(&mut self, e: EncryptStreamError<E>) -> Result<Bytes, EncryptStreamError<E>> {
        self.is_done = true;
        self.queue.clear();
        self.buffer.zeroize();
        Err(e)
    }
    pub(super) fn process(
        &mut self,
        data: Option<&[u8]>,
        is_final: bool,
    ) -> Result<Option<Bytes>, EncryptStreamError<E>> {
        if let Some(data) = data {
            self.buffer.put(data);
        }
        loop {
            if self.buffer.is_empty() {
                return Ok(None);
            }
            if self.buffer.len() <= self.block_size() {
                if is_final {
                    let segment = self.encrypt_segment(is_final)?;
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
    ) -> Result<Bytes, EncryptStreamError<E>> {
        let mut buf = if !is_final {
            let buf = self.buffer.split_off(self.buffer.len() - self.block_size());
            mem::replace(&mut self.buffer, buf)
        } else {
            self.buffer.split()
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
            let mut buf_with_header = BytesMut::with_capacity(header.len() + buf.len());
            buf_with_header.put_header(header);
            buf_with_header.put(buf);
            buf = buf_with_header;
        }
        Ok(buf.freeze())
    }
}

pub trait DecryptStream: TryStream {
    fn encrypt<A>(
        self,
        segment_size: Segment,
        additional_data: A,
        aead: &Aead,
    ) -> Result<Encrypt<Self, Self::Ok, Self::Error>, EncryptError>
    where
        Self: Sized,
        Self::Ok: AsRef<[u8]>,
        Self::Error: std::error::Error,
        A: AsRef<[u8]>,
    {
        Encrypt::new(self, segment_size, additional_data, aead)
    }
}

#[pin_project]
pub struct Decrypt<S, T, E>
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

impl<S, T, E> Stream for Decrypt<S, T, E>
where
    S: TryStream<Ok = T, Error = E>,
    T: AsRef<[u8]>,
    E: std::error::Error,
{
    type Item = Result<Bytes, EncryptStreamError<E>>;

    fn poll_next(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> Poll<Option<Self::Item>> {
        let mut this = self.project();
        let mut inner = this.inner;
        if inner.is_done {
            return Poll::Ready(None);
        }
        loop {
            match this.stream.as_mut().try_poll_next(cx) {
                Poll::Ready(Some(Ok(data))) => match inner.process(Some(data.as_ref()), false) {
                    Ok(Some(next)) => return Poll::Ready(Some(Ok(next))),
                    Ok(None) => continue,
                    Err(e) => return Poll::Ready(Some(inner.err(e))),
                },
                Poll::Pending => todo!(),
                Poll::Ready(Some(Err(e))) => {
                    return Poll::Ready(Some(inner.err(EncryptStreamError::Upstream(e))));
                }
                Poll::Pending => todo!(),
            }
        }
    }
}
pub(super) struct StreamDecryptor<E> {
    method: Option<Method>,
    key: Option<Key>,
    salt: Option<Salt>,
    buffer: BytesMut,
    pending: Option<Bytes>,
    _phantom: PhantomData<E>,
}

impl<E> StreamDecryptor<E> {
    pub(super) fn process() -> Result<Option<Bytes>, DecryptStreamError<E>> {
        todo!()
    }
}
