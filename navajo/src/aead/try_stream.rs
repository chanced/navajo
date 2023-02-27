use core::task::Poll::{Pending, Ready};

use alloc::{collections::VecDeque, vec, vec::Vec};
use futures::{stream::FusedStream, Stream, TryStream};
use pin_project::pin_project;

use crate::{
    error::{DecryptStreamError, EncryptTryStreamError},
    rand::Random,
    Aad, Aead, SystemRandom,
};

use super::{Decryptor, Encryptor, Segment};

pub trait AeadTryStream: TryStream {
    fn encrypt<T, A>(self, segment: Segment, aad: Aad<A>, aead: T) -> EncryptTryStream<Self, A>
    where
        Self: Sized,
        Self::Ok: AsRef<[u8]>,
        Self::Error: Send + Sync,
        T: AsRef<Aead>,
        A: AsRef<[u8]> + Send + Sync,
    {
        EncryptTryStream::new(self, segment, aad, aead)
    }
    fn decrypt<K, A>(self, aad: Aad<A>, aead: K) -> DecryptTryStream<Self, K, A>
    where
        Self: Sized,
        Self::Ok: AsRef<[u8]>,
        Self::Error: Send + Sync,
        K: AsRef<Aead> + Send + Sync,
        A: AsRef<[u8]> + Send + Sync,
    {
        DecryptTryStream::new(self, aead, aad)
    }
}
impl<T> AeadTryStream for T
where
    T: TryStream,
    T::Ok: AsRef<[u8]>,
    T::Error: Send + Sync,
{
}

#[pin_project]
pub struct EncryptTryStream<S, A, Rand = SystemRandom>
where
    S: TryStream + Sized,
    S::Ok: AsRef<[u8]>,
    S::Error: Send + Sync,
    A: AsRef<[u8]> + Send + Sync,
    Rand: Random,
{
    #[pin]
    stream: S,
    encryptor: Option<Encryptor<Vec<u8>, Rand>>,
    queue: VecDeque<Vec<u8>>,
    aad: Aad<A>,
    done: bool,
}

impl<S, A> EncryptTryStream<S, A>
where
    S: TryStream + Sized,
    S::Ok: AsRef<[u8]>,
    S::Error: Send + Sync,
    A: AsRef<[u8]> + Send + Sync,
{
    pub fn new<K>(stream: S, segment: Segment, aad: Aad<A>, aead: K) -> Self
    where
        K: AsRef<Aead>,
    {
        let encryptor = Encryptor::new(aead.as_ref(), Some(segment), vec![]);
        Self {
            stream,
            encryptor: Some(encryptor),
            queue: VecDeque::new(),
            aad,
            done: false,
        }
    }
}
impl<S, D> FusedStream for EncryptTryStream<S, D>
where
    S: TryStream + Sized,
    S::Ok: AsRef<[u8]>,
    S::Error: Send + Sync,
    D: AsRef<[u8]> + Send + Sync,
{
    fn is_terminated(&self) -> bool {
        self.done
    }
}

impl<S, D> Stream for EncryptTryStream<S, D>
where
    S: TryStream,
    S::Ok: AsRef<[u8]>,
    S::Error: Send + Sync,
    D: AsRef<[u8]> + Send + Sync,
{
    type Item = Result<Vec<u8>, EncryptTryStreamError<S::Error>>;
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

            if this.encryptor.is_none() {
                *this.done = true;
                return Ready(None);
            }
            let mut encryptor = this.encryptor.take().unwrap();
            match this.stream.as_mut().try_poll_next(cx) {
                Ready(data) => match data {
                    Some(resp) => match resp {
                        Ok(data) => {
                            let result = encryptor.update(Aad(this.aad.as_ref()), data.as_ref());
                            match result {
                                Err(e) => {
                                    *this.done = true;
                                    return Ready(Some(Err(e.into())));
                                }
                                Ok(_) => {
                                    if let Some(ciphertext) = encryptor.next() {
                                        this.queue.push_back(ciphertext);
                                    }
                                    this.encryptor.replace(encryptor);
                                }
                            }
                        }
                        Err(err) => {
                            *this.done = true;
                            return Ready(Some(Err(EncryptTryStreamError::Upstream(err))));
                        }
                    },
                    None => {
                        let result = encryptor.finalize(Aad(this.aad.as_ref()));
                        match result {
                            Err(e) => {
                                *this.done = true;
                                return Ready(Some(Err(e.into())));
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
pub struct DecryptTryStream<S, K, A, Rand = SystemRandom>
where
    S: TryStream + Sized,
    K: AsRef<Aead> + Send + Sync,
    A: AsRef<[u8]> + Send + Sync,
    Rand: Random,
{
    #[pin]
    stream: S,
    decryptor: Option<Decryptor<K, Vec<u8>, Rand>>,
    queue: VecDeque<Vec<u8>>,
    aad: Aad<A>,
    done: bool,
}

impl<S, K, A> DecryptTryStream<S, K, A>
where
    S: TryStream + Sized,
    K: AsRef<Aead> + Send + Sync,
    A: AsRef<[u8]> + Send + Sync,
{
    pub fn new(stream: S, aead: K, aad: Aad<A>) -> Self {
        let decryptor = Decryptor::new(aead, vec![]);
        Self {
            aad,
            stream,
            decryptor: Some(decryptor),
            queue: VecDeque::new(),
            done: false,
        }
    }
}

impl<S, K, D> Stream for DecryptTryStream<S, K, D>
where
    S: TryStream,
    S::Ok: AsRef<[u8]>,
    S::Error: Send + Sync,
    K: AsRef<Aead> + Send + Sync,
    D: AsRef<[u8]> + Send + Sync,
{
    type Item = Result<Vec<u8>, DecryptStreamError<S::Error>>;
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
            let mut decryptor = this.decryptor.take().unwrap();

            match this.stream.as_mut().try_poll_next(cx) {
                Ready(resp) => match resp {
                    Some(result) => match result {
                        Ok(data) => {
                            decryptor.update(Aad(this.aad.as_ref()), data.as_ref())?;
                            match decryptor.next(Aad(this.aad.as_ref())) {
                                Err(e) => {
                                    *this.done = true;
                                    return Ready(Some(Err(e.into())));
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
                        Err(err) => {
                            *this.done = true;
                            return Ready(Some(Err(DecryptStreamError::Upstream(err))));
                        }
                    },
                    None => {
                        let result = decryptor.finalize(Aad(this.aad.as_ref()));
                        match result {
                            Err(e) => {
                                *this.done = true;
                                return Ready(Some(Err(e.into())));
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
    use alloc::string::String;
    use futures::{stream, StreamExt, TryStreamExt};

    fn to_try_stream(d: Vec<u8>) -> Result<Vec<u8>, String> {
        Ok(d)
    }
    #[cfg(feature = "std")]
    #[tokio::test]
    async fn test_stream_roundtrip() {
        let data_stream = stream::iter(vec![
            Vec::from(&b"hello"[..]),
            Vec::from(&b" "[..]),
            Vec::from(&b"world"[..]),
        ])
        .map(to_try_stream);

        let aead = Aead::new(Algorithm::Aes256Gcm, None);
        let encrypt_stream =
            data_stream.encrypt(Segment::FourKilobytes, Aad::empty(), aead.clone());
        let ciphertext: Vec<u8> = encrypt_stream.try_concat().await.unwrap();

        let ciphertext_stream =
            stream::iter(ciphertext.chunks(40).map(Vec::from)).map(to_try_stream);
        let decrypt_stream = ciphertext_stream.decrypt(Aad::empty(), aead);
        let result = decrypt_stream.try_concat().await.unwrap();
        assert_eq!(result, b"hello world");
    }
    #[cfg(feature = "std")]
    #[tokio::test]
    async fn test_stream_with_aad_roundtrip() {
        let mut data = vec![0u8; 5556];
        let rand = SystemRandom::new();
        rand.fill(&mut data);
        let data_stream = stream::iter(data.chunks(122).map(Vec::from)).map(to_try_stream);
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
        let ciphertext_stream =
            stream::iter(ciphertext.chunks(40).map(Vec::from)).map(to_try_stream);
        let cleartext: Vec<u8> = ciphertext_stream
            .decrypt(Vec::from(&b"additional data"[..]).into(), aead)
            .try_concat()
            .await
            .unwrap();
        assert_eq!(cleartext, data);
    }
}
