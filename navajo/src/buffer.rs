use alloc::vec::Vec;

use rust_crypto_aead::Buffer as RustCryptoBuffer;
use zeroize::{Zeroize, ZeroizeOnDrop};
pub trait Buffer: AsRef<[u8]> + AsMut<[u8]> + for<'a> Extend<&'a u8> + Default {
    fn truncate(&mut self, len: usize);
    fn split_off(&mut self, pos: usize) -> Self;
    fn clear(&mut self);
    fn len(&self) -> usize {
        self.as_ref().len()
    }
    fn is_empty(&self) -> bool {
        self.as_ref().is_empty()
    }
    fn extend_from_slice(&mut self, other: &[u8]) {
        self.extend(other.iter())
    }
}

impl Buffer for Vec<u8> {
    fn truncate(&mut self, len: usize) {
        self.truncate(len)
    }
    fn split_off(&mut self, pos: usize) -> Self {
        Vec::split_off(self, pos)
    }

    fn clear(&mut self) {
        Vec::clear(self)
    }
    fn len(&self) -> usize {
        Vec::len(self)
    }
    fn is_empty(&self) -> bool {
        Vec::is_empty(self)
    }
}
#[cfg(feature = "bytes")]
impl Buffer for bytes::BytesMut {
    fn truncate(&mut self, len: usize) {
        self.truncate(len)
    }
    fn split_off(&mut self, pos: usize) -> Self {
        bytes::BytesMut::split_off(self, pos)
    }

    fn clear(&mut self) {
        bytes::BytesMut::clear(self)
    }
    fn len(&self) -> usize {
        bytes::BytesMut::len(self)
    }
    fn is_empty(&self) -> bool {
        bytes::BytesMut::is_empty(self)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Default)]
pub struct BufferZeroizer<B: Buffer>(pub B);

impl<B> Buffer for BufferZeroizer<B>
where
    B: Buffer,
{
    fn truncate(&mut self, len: usize) {
        self.0.truncate(len)
    }
    fn split_off(&mut self, pos: usize) -> Self {
        Self(self.0.split_off(pos))
    }

    fn clear(&mut self) {
        self.0.clear()
    }
    fn len(&self) -> usize {
        self.0.len()
    }
}

impl ZeroizeOnDrop for BufferZeroizer<Vec<u8>> {}

impl<B> Drop for BufferZeroizer<B>
where
    B: Buffer,
{
    fn drop(&mut self) {
        self.zeroize()
    }
}

impl<B> Zeroize for BufferZeroizer<B>
where
    B: Buffer,
{
    fn zeroize(&mut self) {
        self.0.as_mut().iter_mut().zeroize();
        self.clear();
    }
}

impl<B> AsMut<[u8]> for BufferZeroizer<B>
where
    B: Buffer,
{
    fn as_mut(&mut self) -> &mut [u8] {
        self.0.as_mut()
    }
}
impl<B> AsRef<[u8]> for BufferZeroizer<B>
where
    B: Buffer,
{
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}
impl<'a, B> Extend<&'a u8> for BufferZeroizer<B>
where
    B: Buffer,
{
    fn extend<I: IntoIterator<Item = &'a u8>>(&mut self, iter: I) {
        self.0.extend(iter)
    }
}
pub(crate) struct RcBuffer<'b, B>(pub(crate) &'b mut B)
where
    B: Buffer;

impl<'b, B> RustCryptoBuffer for RcBuffer<'b, B>
where
    B: Buffer,
{
    fn extend_from_slice(&mut self, other: &[u8]) -> rust_crypto_aead::Result<()> {
        self.0.extend(other.iter());
        Ok(())
    }

    fn truncate(&mut self, len: usize) {
        self.0.truncate(len)
    }
}

impl<'b, B> AsMut<[u8]> for RcBuffer<'b, B>
where
    B: Buffer,
{
    fn as_mut(&mut self) -> &mut [u8] {
        self.0.as_mut()
    }
}
impl<'b, B> AsRef<[u8]> for RcBuffer<'b, B>
where
    B: Buffer,
{
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}

pub(crate) fn prepend_to_buffer<B: Buffer>(data: &mut B, header: &[u8]) {
    let original_len = data.as_ref().len();
    let header_len = header.len();
    let shifted = data.as_ref()[original_len - header_len..].to_vec();
    data.extend(shifted.iter());
    // shifts the data to the right by header len
    let data = data.as_mut();
    #[allow(clippy::needless_range_loop)]
    for i in (0..original_len - header_len).rev() {
        data[i + header_len] = data[i];
        if i < header_len {
            data[i] = header[i];
        }
    }
}
#[cfg(test)]
mod tests {
    use alloc::vec;

    use crate::Buffer;

    use super::prepend_to_buffer;
    fn split_off<B: Buffer>(b: &mut B) -> B {
        b.split_off(3)
    }
    #[test]
    fn test_prepend_header() {
        let header = [0, 1, 2, 3, 4];
        let mut data = vec![10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21];

        prepend_to_buffer(&mut data, &header);
        assert_eq!(
            data,
            vec![0, 1, 2, 3, 4, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21]
        )
    }

    #[test]
    fn test_split_off_vec() {
        let mut data = vec![0, 1, 2, 3, 4, 5, 6, 7, 8, 9];

        let res = split_off(&mut data);
        assert_eq!(res, vec![3, 4, 5, 6, 7, 8, 9]);
        assert_eq!(data, vec![0, 1, 2]);
    }

    #[cfg(feature = "bytes")]
    #[test]
    fn test_split_off_bytes() {
        let mut data = bytes::BytesMut::from(&vec![0, 1, 2, 3, 4, 5, 6, 7, 8, 9][..]);
        let res = split_off(&mut data);
        assert_eq!(res, vec![3, 4, 5, 6, 7, 8, 9]);
        assert_eq!(data, vec![0, 1, 2]);
    }
}
