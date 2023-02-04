#[derive(Clone, Debug)]
pub struct Tag {
    bytes: Vec<u8>,
    len: usize,
    // header: Header,
    // algo: Hash,
}

impl PartialEq for Tag {
    fn eq(&self, other: &Self) -> bool {
        self.bytes[..self.len] == other.bytes[..other.len]
    }
}

pub(super) struct InternalTag {

}
