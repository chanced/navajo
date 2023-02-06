use std::sync::Arc;

use rayon::ThreadPool;

use super::{context::Context, Key, Tag};

pub(super) struct Hasher {
    keys: Vec<Arc<Key>>,
    primary_key: Arc<Key>,
    contexts: Vec<Context>,
}
impl Hasher {
    pub(super) fn new(primary_key: Arc<Key>, keys: Vec<Arc<Key>>) -> Self {
        let mut ctxs = Vec::with_capacity(keys.len());
        for key in &keys {
            ctxs.push(Context::new(&key.inner));
        }
        Self {
            keys,
            primary_key,
            contexts: ctxs,
        }
    }
}
