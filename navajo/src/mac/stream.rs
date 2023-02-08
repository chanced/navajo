use core::marker::PhantomData;

use futures::TryStream;
use pin_project::pin_project;

use super::{Hasher, Mac, Tag};

pub trait MacStream: TryStream {
    fn compute_mac<M>(self, stream: Self, mac: M) -> ComputeMacStream<Self, Self::Ok, Self::Error>
    where
        M: AsRef<Mac>,
        Self: Sized,
        Self::Ok: AsRef<[u8]>,
        Self::Error: Send + Sync,
    {
        let mac = mac.as_ref();
        ComputeMacStream {
            stream,
            hasher: Hasher::new(mac.keyring.keys().iter()),
            _phantom: PhantomData,
        }
    }

    fn verify_mac<M>(self, stream: Self, tag: M) -> VerifyMacStream<Self, Self::Ok, Self::Error>
    where
        Self: Sized,
        Self::Ok: AsRef<[u8]>,
        Self::Error: Send + Sync,
        M: AsRef<Tag> + Send + Sync,
    {
        VerifyMacStream {
            stream,
            _phantom: PhantomData,
        }
    }
}

#[pin_project]
pub struct ComputeMacStream<S, T, E>
where
    S: TryStream<Ok = T, Error = E>,
    T: AsRef<[u8]>,
    E: Send + Sync,
{
    #[pin]
    stream: S,
    hasher: Hasher,
    _phantom: PhantomData<(T, E)>,
}

#[pin_project]
pub struct VerifyMacStream<S, T, E>
where
    S: TryStream<Ok = T, Error = E>,
    T: AsRef<[u8]>,
    E: Send + Sync,
{
    #[pin]
    stream: S,
    _phantom: PhantomData<(T, E)>,
}
