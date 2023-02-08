use crate::error::MacVerificationError;

use super::{hasher::Hasher, Tag};

pub(super) struct Verifier<T>
where
    T: AsRef<Tag> + Send + Sync,
{
    tag: T,
    hasher: Hasher,
}
impl<T> Verifier<T>
where
    T: AsRef<Tag> + Send + Sync,
{
    pub(super) fn new(tag: T) -> Self {
        let t = tag.as_ref();
        let hasher = Hasher::new(t.keys());
        Self { tag, hasher }
    }
    pub(super) fn update(&mut self, data: &[u8], buf_size: usize) {
        self.hasher.update(data, buf_size)
    }

    pub(super) fn verify(&self) -> Result<(), MacVerificationError> {
        let mut computed_tag = self.hasher.finalize();
		let tag = self.tag.as_ref();
		if tag.is
    }
}
