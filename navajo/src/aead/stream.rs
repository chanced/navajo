use core::task::Poll::{Pending, Ready};

use alloc::collections::VecDeque;
use futures::{
    stream::{Fuse, FusedStream},
    Stream, StreamExt,
};
use pin_project::pin_project;

use crate::{
    error::{DecryptError, EncryptError},
    Aad, Aead,
};

use super::{Decryptor, Encryptor, Segment};

pub trait AeadStream: Stream {
    fn encrypt<T, A>(self, segment: Segment, aad: Aad<A>, aead: T) -> EncryptStream<Self, A>
    where
        Self: Sized,
        Self::Item: AsRef<[u8]>,
        T: AsRef<Aead>,
        A: AsRef<[u8]> + Send + Sync,
    {
        EncryptStream::new(self, segment, aad, aead)
    }
    fn decrypt<K, A>(self, aad: Aad<A>, aead: K) -> DecryptStream<Self, K, A>
    where
        Self: Sized,
        Self::Item: AsRef<[u8]>,
        K: AsRef<Aead> + Send + Sync,
        A: AsRef<[u8]> + Send + Sync,
    {
        DecryptStream::new(self, aead, aad)
    }
}
impl<T> AeadStream for T
where
    T: Stream,
    T::Item: AsRef<[u8]>,
{
}

#[pin_project]
pub struct EncryptStream<S, A>
where
    S: Stream + Sized,
    A: AsRef<[u8]>,
{
    #[pin]
    stream: Fuse<S>,
    encryptor: Option<Encryptor<Vec<u8>>>,
    queue: VecDeque<Vec<u8>>,
    aad: Aad<A>,
    done: bool,
}

impl<S, A> EncryptStream<S, A>
where
    S: Stream + Sized,
    A: AsRef<[u8]> + Send + Sync,
{
    pub fn new<K>(stream: S, segment: Segment, aad: Aad<A>, aead: K) -> Self
    where
        K: AsRef<Aead>,
    {
        let encryptor = Encryptor::new(aead.as_ref(), Some(segment), vec![]);
        Self {
            stream: stream.fuse(),
            encryptor: Some(encryptor),
            queue: VecDeque::new(),
            aad,
            done: false,
        }
    }
}
impl<S, D> FusedStream for EncryptStream<S, D>
where
    S: Stream + Sized,
    S::Item: AsRef<[u8]>,
    D: AsRef<[u8]> + Send + Sync,
{
    fn is_terminated(&self) -> bool {
        self.done
    }
}

impl<S, D> Stream for EncryptStream<S, D>
where
    S: Stream,
    S::Item: AsRef<[u8]>,
    D: AsRef<[u8]> + Send + Sync,
{
    type Item = Result<Vec<u8>, EncryptError>;
    fn poll_next(
        self: core::pin::Pin<&mut Self>,
        cx: &mut core::task::Context<'_>,
    ) -> core::task::Poll<Option<Self::Item>> {
        let mut this = self.project();
        loop {
            if *this.done {
                return Ready(None);
            }
            if let Some(next) = this.queue.pop_front() {
                return Ready(Some(Ok(next)));
            }
            if this.stream.is_terminated() {
                *this.done = true;
                return Ready(None);
            }
            if this.encryptor.is_none() {
                *this.done = true;
                return Ready(None);
            }
            let mut encryptor = this.encryptor.take().unwrap();
            match this.stream.as_mut().poll_next(cx) {
                Ready(data) => match data {
                    Some(data) => {
                        let result = encryptor.update(Aad(this.aad.as_ref()), data.as_ref());
                        match result {
                            Err(e) => {
                                *this.done = true;
                                return Ready(Some(Err(e)));
                            }
                            Ok(_) => {
                                if let Some(ciphertext) = encryptor.next() {
                                    this.queue.push_back(ciphertext);
                                }
                                this.encryptor.replace(encryptor);
                            }
                        }
                    }
                    None => {
                        let result = encryptor.finalize(Aad(this.aad.as_ref()));
                        match result {
                            Err(e) => {
                                *this.done = true;
                                return Ready(Some(Err(e)));
                            }
                            Ok(iter) => {
                                this.queue.extend(iter);
                            }
                        }
                    }
                },
                Pending => return Pending,
            }
        }
    }
}
#[pin_project]
pub struct DecryptStream<S, K, A>
where
    S: Stream + Sized,
    K: AsRef<Aead> + Send + Sync,
    A: AsRef<[u8]>,
{
    #[pin]
    stream: Fuse<S>,
    decryptor: Option<Decryptor<K, Vec<u8>>>,
    queue: VecDeque<Vec<u8>>,
    aad: Aad<A>,
    done: bool,
}

impl<S, K, A> DecryptStream<S, K, A>
where
    S: Stream,
    K: AsRef<Aead> + Send + Sync,
    A: AsRef<[u8]> + Send + Sync,
{
    pub fn new(stream: S, aead: K, aad: Aad<A>) -> Self {
        let decryptor = Decryptor::new(aead, vec![]);
        Self {
            aad,
            stream: stream.fuse(),
            decryptor: Some(decryptor),
            queue: VecDeque::new(),
            done: false,
        }
    }
}

impl<S, K, D> Stream for DecryptStream<S, K, D>
where
    S: Stream,
    S::Item: AsRef<[u8]>,
    K: AsRef<Aead> + Send + Sync,
    D: AsRef<[u8]> + Send + Sync,
{
    type Item = Result<Vec<u8>, DecryptError>;
    fn poll_next(
        self: core::pin::Pin<&mut Self>,
        cx: &mut core::task::Context<'_>,
    ) -> core::task::Poll<Option<Self::Item>> {
        let mut this = self.project();
        loop {
            if *this.done {
                return Ready(None);
            }
            if let Some(next) = this.queue.pop_front() {
                return Ready(Some(Ok(next)));
            }
            if this.decryptor.is_none() {
                return Ready(None);
            }
            if this.stream.is_terminated() {
                return Ready(None);
            }
            let mut decryptor = this.decryptor.take().unwrap();
            match this.stream.as_mut().poll_next(cx) {
                Ready(data) => match data {
                    Some(data) => {
                        decryptor.update(Aad(this.aad.as_ref()), data.as_ref())?;
                        let result = decryptor.next(Aad(this.aad.as_ref()));
                        match result {
                            Err(e) => {
                                *this.done = true;
                                return Ready(Some(Err(e)));
                            }
                            Ok(Some(cleartext)) => {
                                this.queue.push_back(cleartext);
                                this.decryptor.replace(decryptor);
                            }
                            Ok(None) => {
                                this.decryptor.replace(decryptor);
                            }
                        }
                    }
                    None => {
                        let result = decryptor.finalize(Aad(this.aad.as_ref()));
                        match result {
                            Err(e) => {
                                *this.done = true;
                                return Ready(Some(Err(e)));
                            }
                            Ok(iter) => {
                                this.queue.extend(iter);
                            }
                        }
                    }
                },
                Pending => return Pending,
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::aead::Algorithm;
    use futures::{stream, TryStreamExt};

    #[tokio::test]
    async fn test_stream_roundtrip() {
        let data_stream = stream::iter(vec![
            Vec::from(&b"hello"[..]),
            Vec::from(&b" "[..]),
            Vec::from(&b"world"[..]),
        ]);
        let aead = Aead::new(Algorithm::Aes256Gcm, None);
        let encrypt_stream =
            data_stream.encrypt(Segment::FourKilobytes, Aad::empty(), aead.clone());
        let ciphertext: Vec<u8> = encrypt_stream.try_concat().await.unwrap();

        let decrypt_stream =
            stream::iter(ciphertext.chunks(40).map(Vec::from)).decrypt(Aad::empty(), aead);
        let result = decrypt_stream.try_concat().await.unwrap();
        assert_eq!(result, b"hello world");
    }
    #[tokio::test]
    async fn test_stream_with_aad_roundtrip() {
        let mut data = vec![0u8; 5556];
        crate::rand::fill(&mut data);
        let data_stream = stream::iter(data.chunks(122).map(Vec::from));
        let algorithm = Algorithm::Aes256Gcm;
        let aead = Aead::new(algorithm, None);
        let encrypt_stream = data_stream.encrypt(
            Segment::FourKilobytes,
            Aad(Vec::from(&b"additional data"[..])),
            aead.clone(),
        );
        let result: Vec<Vec<u8>> = encrypt_stream.try_collect().await.unwrap();

        let ciphertext = result.concat();

        println!("ciphertext: {}", ciphertext.len());

        let cleartext: Vec<u8> = stream::iter(ciphertext.chunks(40).map(Vec::from))
            .decrypt(Aad(Vec::from(&b"additional data"[..])), aead)
            .try_concat()
            .await
            .unwrap();
        assert_eq!(cleartext, data);
    }
}
