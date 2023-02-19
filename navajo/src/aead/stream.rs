use core::task::Poll::{Pending, Ready};

use alloc::collections::VecDeque;
use futures::{
    stream::{Fuse, FusedStream},
    Stream, StreamExt,
};
use pin_project::pin_project;

use crate::{error::EncryptError, Aead, Buffer};

use super::{Decryptor, Encryptor, Segment};

pub trait AeadStream: Stream
where
    Self: Sized,
    Self::Item: AsRef<[u8]>,
{
    fn encrypt_stream<T, D, B>(
        s: Self,
        segment: Segment,
        additional_data: D,
        buffer: B,
        aead: T,
    ) -> EncryptStream<Self, D, B>
    where
        T: AsRef<Aead>,
        B: Buffer,
        D: AsRef<[u8]> + Send + Sync,
    {
        EncryptStream::new(s, segment, additional_data, buffer, aead)
    }
    fn decrypt_stream<K>(s: Self, aead: K) -> DecryptStream<Self, K>
    where
        K: AsRef<Aead> + Send + Sync,
    {
        DecryptStream::new(s, aead)
    }
}

impl<T> AeadStream for T
where
    T: Stream,
    T::Item: AsRef<[u8]>,
{
}

#[pin_project]
pub struct EncryptStream<S, D, B>
where
    S: Stream + Sized,
    S::Item: AsRef<[u8]>,
    B: Buffer,
    D: AsRef<[u8]> + Send + Sync,
{
    #[pin]
    stream: Fuse<S>,
    encryptor: Option<Encryptor<B>>,
    queue: VecDeque<B>,
    additional_data: D,
}

impl<S, D, B> EncryptStream<S, D, B>
where
    S: Stream,
    S::Item: AsRef<[u8]>,
    B: Buffer,
    D: AsRef<[u8]> + Send + Sync,
{
    pub fn new<K>(stream: S, segment: Segment, additional_data: D, buffer: B, aead: K) -> Self
    where
        K: AsRef<Aead>,
    {
        let encryptor = Encryptor::new(aead.as_ref(), Some(segment), buffer);
        Self {
            stream: stream.fuse(),
            encryptor: Some(encryptor),
            queue: VecDeque::new(),
            additional_data,
        }
    }
}

impl<S, D, B> Stream for EncryptStream<S, D, B>
where
    S: Stream,
    S::Item: AsRef<[u8]>,
    B: Buffer,
    D: AsRef<[u8]> + Send + Sync,
{
    type Item = Result<B, EncryptError>;

    fn poll_next(
        self: core::pin::Pin<&mut Self>,
        cx: &mut core::task::Context<'_>,
    ) -> core::task::Poll<Option<Self::Item>> {
        let mut this = self.project();
        loop {
            if let Some(next) = this.queue.pop_front() {
                return Ready(Some(Ok(next)));
            }
            if this.stream.is_terminated() {
                return Ready(None);
            }
            if this.encryptor.is_none() {
                return Ready(None);
            }
            match this.stream.as_mut().poll_next(cx) {
                Ready(data) => match data {
                    Some(data) => {
                        let aad = self.additional_data.as_ref();
                        let mut encryptor = this.encryptor.take().unwrap();
                        let result = encryptor.update(aad, data.as_ref());
                        match result {
                            Err(e) => return Ready(Some(Err(e))),
                            Ok(_) => {
                                if let Some(ciphertext) = encryptor.next() {
                                    this.queue.push_back(ciphertext);
                                }
                            }
                        }
                    }
                    None => {
                        let encryptor = this.encryptor.take().unwrap();
                        let result = encryptor.finalize(this.additional_data.as_ref());
                        match result {
                            Err(e) => return Ready(Some(Err(e))),
                            Ok(iter) => {
                                iter.map(|data| this.queue.push_back(data));
                            }
                        }
                    }
                },
                Pending => return Pending,
            }
        }
    }
}

pub struct DecryptStream<S, K>
where
    S: Stream,
    S::Item: AsRef<[u8]>,
    K: AsRef<Aead> + Send + Sync,
{
    stream: S,
    decryptor: Decryptor<K, Vec<u8>>,
}

impl<S, K> DecryptStream<S, K>
where
    S: Stream,
    S::Item: AsRef<[u8]>,
    K: AsRef<Aead> + Send + Sync,
{
    pub fn new(stream: S, aead: K) -> Self {
        let decryptor = Decryptor::new(aead, vec![]);
        Self { stream, decryptor }
    }
}

impl<S, K> Stream for DecryptStream<S, K>
where
    S: Stream,
    S::Item: AsRef<[u8]>,
    K: AsRef<Aead> + Send + Sync,
{
    type Item = Vec<u8>;

    fn poll_next(
        self: core::pin::Pin<&mut Self>,
        cx: &mut core::task::Context<'_>,
    ) -> core::task::Poll<Option<Self::Item>> {
        todo!()
    }
}
