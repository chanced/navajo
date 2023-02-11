use alloc::vec::Vec;

use super::Method;
#[derive(Clone)]
pub(super) struct PartialHeader {
    pub(super) id: Option<u32>,
    pub(super) method: Option<Method>,
    pub(super) nonce: Option<Vec<u8>>,
    pub(super) salt: Option<Option<Vec<u8>>>,
}
