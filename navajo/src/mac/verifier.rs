use crate::{error::MacVerificationError, key::Key};

use super::{hasher::Hasher, material::Material, Tag};

pub(super) struct Verifier {
    tag: Tag,
    hasher: Hasher,
}
impl Verifier {
    pub(super) fn new(keys: &[Key<Material>], tag: &Tag) -> Self {
        let _t = tag.as_ref();
        let hasher = Hasher::new(keys);
        Self {
            tag: tag.clone(),
            hasher,
        }
    }
    pub(super) fn update(&mut self, data: &[u8], buf_size: usize) {
        self.hasher.update(data, buf_size)
    }

    pub(super) fn finalize(self) -> Result<Tag, MacVerificationError> {
        let computed = self.hasher.finalize();
        if self.tag == computed {
            Ok(computed)
        } else {
            Err(MacVerificationError)
        }
    }
}
