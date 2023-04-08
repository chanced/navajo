use core::task::Poll::{Pending, Ready};

use super::{Decryptor, Encryptor, Segment};
use crate::{
    error::{DecryptError, EncryptError},
    Aad, Aead, Rng, SystemRng,
};
use alloc::{collections::VecDeque, vec, vec::Vec};
use futures::{
    stream::{Fuse, FusedStream},
    Stream, StreamExt,
};
use pin_project::pin_project;

pub trait AeadStream: Stream {
    fn encrypt<C, A>(self, segment: Segment, aad: Aad<A>, aead: C) -> EncryptStream<Self, A>
    where
        Self: Sized,
        Self::Item: AsRef<[u8]>,
        C: AsRef<Aead> + Send + Sync,
        A: AsRef<[u8]> + Send + Sync,
    {
        EncryptStream::new(SystemRng, self, segment, aad, aead)
    }
    fn decrypt<C, A>(self, aad: Aad<A>, cipher: C) -> DecryptStream<Self, C, A>
    where
        Self: Sized,
        Self::Item: AsRef<[u8]>,
        C: AsRef<Aead> + Send + Sync,
        A: AsRef<[u8]> + Send + Sync,
    {
        DecryptStream::new(SystemRng, self, cipher, aad)
    }
}

impl<T> AeadStream for T
where
    T: Stream,
    T::Item: AsRef<[u8]>,
{
}

#[pin_project]
pub struct EncryptStream<S, A, N = SystemRng>
where
    S: Stream + Sized,
    A: AsRef<[u8]>,
    N: Rng,
{
    #[pin]
    stream: Fuse<S>,
    encryptor: Option<Encryptor<Vec<u8>, N>>,
    queue: VecDeque<Vec<u8>>,
    aad: Aad<A>,
    done: bool,
}

impl<S, A, N> EncryptStream<S, A, N>
where
    S: Stream + Sized,
    A: AsRef<[u8]> + Send + Sync,
    N: Rng,
{
    pub fn new<C>(rng: N, stream: S, segment: Segment, aad: Aad<A>, aead: C) -> Self
    where
        C: AsRef<Aead> + Send + Sync,
    {
        let encryptor = Encryptor::new(rng, aead.as_ref(), Some(segment), vec![]);
        Self {
            stream: stream.fuse(),
            encryptor: Some(encryptor),
            queue: VecDeque::new(),
            aad,
            done: false,
        }
    }
}
impl<S, A, N> FusedStream for EncryptStream<S, A, N>
where
    S: Stream + Sized,
    S::Item: AsRef<[u8]>,
    A: AsRef<[u8]> + Send + Sync,
    N: Rng,
{
    fn is_terminated(&self) -> bool {
        self.done
    }
}

impl<S, D, N> Stream for EncryptStream<S, D, N>
where
    S: Stream,
    S::Item: AsRef<[u8]>,
    D: AsRef<[u8]> + Send + Sync,
    N: Rng,
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
pub struct DecryptStream<S, C, A, N = SystemRng>
where
    N: Rng,
    S: Stream + Sized,
    C: AsRef<Aead> + Send + Sync,
    A: AsRef<[u8]>,
{
    #[pin]
    stream: Fuse<S>,
    decryptor: Option<Decryptor<C, Vec<u8>>>,
    queue: VecDeque<Vec<u8>>,
    aad: Aad<A>,
    done: bool,
    rng: N,
}

impl<S, C, A, N> DecryptStream<S, C, A, N>
where
    N: Rng,
    S: Stream,
    C: AsRef<Aead> + Send + Sync,
    A: AsRef<[u8]> + Send + Sync,
{
    pub fn new(rng: N, stream: S, cipher: C, aad: Aad<A>) -> Self {
        let decryptor = Decryptor::new(cipher, vec![]);
        Self {
            rng,
            aad,
            stream: stream.fuse(),
            decryptor: Some(decryptor),
            queue: VecDeque::new(),
            done: false,
        }
    }
}

impl<S, C, D, N> Stream for DecryptStream<S, C, D, N>
where
    N: Rng,
    S: Stream,
    S::Item: AsRef<[u8]>,
    C: AsRef<Aead> + Send + Sync,
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
                            Ok(Some(plaintext)) => {
                                this.queue.push_back(plaintext);
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
    #[cfg(feature = "std")]
    #[tokio::test]
    async fn test_stream_roundtrip() {
        use super::*;
        use crate::aead::Algorithm;
        use futures::{stream, TryStreamExt};

        let data_stream = stream::iter(vec![
            Vec::from("hello".as_bytes()),
            Vec::from(" ".as_bytes()),
            Vec::from("world".as_bytes()),
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

    #[cfg(feature = "std")]
    #[tokio::test]
    async fn test_stream_with_aad_roundtrip() {
        use super::*;
        use crate::aead::Algorithm;
        use futures::{stream, TryStreamExt};

        let mut data = vec![0u8; 5556];
        let rng = crate::SystemRng::new();
        rng.fill(&mut data).unwrap();
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

        let plaintext: Vec<u8> = stream::iter(ciphertext.chunks(40).map(Vec::from))
            .decrypt(Aad(Vec::from(&b"additional data"[..])), aead)
            .try_concat()
            .await
            .unwrap();
        assert_eq!(plaintext, data);
    }
}
