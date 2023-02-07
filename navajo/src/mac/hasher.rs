use cfg_if::cfg_if;
use rayon::prelude::*;

use alloc::sync::Arc;
use alloc::{collections::VecDeque, vec::Vec};

#[cfg(feature = "std")]
use std::io::Read;

const BUFFER_SIZE: usize = 64;

use super::{context::Context, Key, Tag};

pub(super) struct Hasher {
    keys: Vec<Arc<Key>>,
    primary_key: Arc<Key>,
    contexts: Vec<Context>,
    #[cfg(not(feature = "std"))]
    buffer: VecDeque<u8>,
    #[cfg(feature = "std")]
    buffer: Vec<u8>,
}
impl Hasher {
    pub(super) fn new(primary_key: Arc<Key>, keys: Vec<Arc<Key>>) -> Self {
        let mut ctxs = Vec::with_capacity(keys.len());
        for key in &keys {
            ctxs.push(Context::new(&key.inner));
        }
        #[cfg(feature = "std")]
        {
            Self {
                keys,
                primary_key,
                contexts: ctxs,
                buffer: Vec::new(),
            }
        }
        #[cfg(not(feature = "std"))]
        Self {
            keys,
            primary_key,
            contexts: ctxs,
            buffer: VecDeque::new(),
        }
    }

    pub(super) fn update(&mut self, data: &[u8]) {
        self.buffer.extend(data.iter());
        while self.buffer.len() >= BUFFER_SIZE {
            let chunk: Vec<u8>;
            #[cfg(feature = "std")]
            {
                let buf = self.buffer.split_off(BUFFER_SIZE);
                chunk = std::mem::replace(&mut self.buffer, buf);
            }
            #[cfg(not(feature = "std"))]
            {
                chunk = self.buffer.drain(..BUFFER_SIZE).collect::<Vec<_>>();
            }
            self.update_chunk(chunk);
        }
    }

    fn update_chunk(&mut self, chunk: Vec<u8>) {
        if self.keys.len() > 1 {
            self.contexts.par_iter_mut().for_each(|ctx| {
                ctx.update(&chunk);
            });
        } else {
            self.contexts.iter_mut().for_each(|ctx| {
                ctx.update(&chunk);
            });
        }
    }
}
cfg_if! {
    if #[cfg(feature="std")] {
        pub struct ComputeRead<R> {
            reader: R,
            hasher: Hasher,
        }

        impl<R> ComputeRead<R>
        where
            R: std::io::Read,
        {
            pub(super) fn new(reader: R, primary_key: Arc<Key>, keys: Vec<Arc<Key>>) -> Self {
                let hasher = Hasher::new(primary_key, keys);
                Self { reader, hasher }
            }
        }

    }
}
