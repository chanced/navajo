use crate::{error::MacVerificationError, key::Key};

use super::{hasher::Hasher, material::Material, Tag};

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
    pub(super) fn new(keys: &[Key<Material>], tag: T) -> Self {
        let _t = tag.as_ref();
        let hasher = Hasher::new(keys);
        Self { tag, hasher }
    }
    pub(super) fn update(&mut self, data: &[u8], buf_size: usize) {
        self.hasher.update(data, buf_size)
    }

    pub(super) fn finalize(self) -> Result<Tag, MacVerificationError> {
        let computed = self.hasher.finalize();
        if self.tag.as_ref() == computed {
            Ok(computed)
        } else {
            Err(MacVerificationError)
        }
    }
}
