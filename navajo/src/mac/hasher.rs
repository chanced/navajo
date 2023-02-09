use alloc::{collections::VecDeque, vec::Vec};
use rayon::prelude::{IntoParallelRefMutIterator, ParallelIterator};

#[cfg(feature = "std")]
use std::io::Read;

const BUFFER_SIZE: usize = 64;

use crate::key::Key;

use super::{context::Context, Material, Tag};

/// Generates a [`Tag`] for the given data using a set of keys.
pub(super) struct Hasher {
    primary_key: Key<Material>,
    contexts: Vec<(Key<Material>, Context)>,
    #[cfg(not(feature = "std"))]
    buffer: VecDeque<u8>,
    #[cfg(feature = "std")]
    buffer: Vec<u8>,
}

impl Hasher {
    pub(super) fn new<'a>(keys: impl Iterator<Item = &'a Key<Material>>) -> Self {
        let mut contexts = Vec::new();
        let mut primary_key = None;
        let mut primary_key_found = false;
        for key in keys {
            if key.status().is_primary() {
                primary_key_found = true;
                primary_key = Some(key.clone());
            } else if !primary_key_found {
                // this shouldn't matter but it's a safeguard to avoid panicing
                primary_key = Some(key.clone());
            }
            contexts.push((key.clone(), Context::new(&key.material().inner)));
        }
        let primary_key = primary_key.expect("keys were empty in Hasher::new\nthis is a bug!\nplease report it to https://github.com/chanced/navajo/issues/new");
        #[cfg(feature = "std")]
        {
            Self {
                primary_key,
                contexts,
                buffer: Vec::new(),
            }
        }
        #[cfg(not(feature = "std"))]
        Self {
            primary_key,
            contexts,
            buffer: VecDeque::new(),
        }
    }

    pub(super) fn update(&mut self, data: &[u8], buf_size: usize) {
        self.buffer.extend(data.iter());

        // there's no reason to keep a buffer if there's only one key
        if self.contexts.len() == 1 {
            let mut buf = self.buffer.split_off(0);
            #[cfg(not(feature = "std"))]
            let buf = buf.make_contiguous();
            self.contexts[0].1.update(&buf);
        }

        // in the event there are mutliple keys, the data is buffered and
        // chunked. This is because updates are possibly run in parallel,
        // resulting in the potential memory usage of n * d where n is the
        // number of keys and d is size of the data.
        while self.buffer.len() >= buf_size {
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
        if self.contexts.len() > 1 {
            self.contexts.par_iter_mut().for_each(|(_, ctx)| {
                ctx.update(&chunk);
            });
        } else {
            self.contexts.iter_mut().for_each(|(_, ctx)| {
                ctx.update(&chunk);
            });
        }
    }
    pub(super) fn finalize(self) -> Tag {
        let mut outputs = Vec::with_capacity(self.contexts.len());
        for (key, ctx) in self.contexts {
            let output = ctx.finalize();
            outputs.push((key, output));
        }
        Tag::new(&self.primary_key, outputs)
    }
}
