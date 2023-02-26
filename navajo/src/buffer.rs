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
    fn prepend_slice(&mut self, slice: &[u8]) {
        let original_len = self.as_ref().len();
        let slice_len = slice.len();
        if original_len > slice_len && !slice.is_empty() {
            let shifted = self.as_ref()[original_len - slice_len..].to_vec();
            self.extend_from_slice(&shifted);
            let data = self.as_mut();
            #[allow(clippy::needless_range_loop)]
            for i in (0..original_len).rev() {
                data[i + slice_len] = data[i];
                if i < slice_len {
                    data[i] = slice[i];
                }
            }
        } else if original_len != 0 && slice_len != 0 {
            let buf = core::mem::take(self);
            self.extend_from_slice(slice);
            self.extend_from_slice(buf.as_ref());
        } else if !slice.is_empty() {
            // data is empty
            self.extend_from_slice(slice);
        }
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
    fn prepend_slice(&mut self, slice: &[u8]) {
        self.splice(0..0, slice.iter().cloned());
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
pub(crate) struct BufferZeroizer<B: Buffer>(pub B);

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

#[cfg(test)]
mod tests {
    use crate::Buffer;
    use alloc::vec;
    use alloc::vec::Vec;

    fn split_off<B: Buffer>(b: &mut B) -> B {
        b.split_off(3)
    }

    #[test]
    fn test_vec_prepend_to_empty_buffer() {
        let header = [0, 1, 2, 3, 4];
        let mut buffer = vec![];
        buffer.prepend_slice(&header);
        assert_eq!(buffer, vec![0, 1, 2, 3, 4])
    }
    #[test]
    fn test_vec_prepend_to_slice_smaller_buffer() {
        let header = [0, 1, 2, 3, 4];
        let mut buffer = vec![5, 6];
        buffer.prepend_slice(&header);
        assert_eq!(buffer, vec![0, 1, 2, 3, 4, 5, 6])
    }

    #[test]
    fn test_vec_prepend_slice_to_slice() {
        let header = [0, 1, 2, 3, 4];
        let mut buffer = vec![10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21];

        buffer.prepend_slice(&header);
        assert_eq!(
            buffer,
            vec![0, 1, 2, 3, 4, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21]
        )
    }

    #[test]
    fn test_vec_prepend_slice_explicit() {
        let origin = vec![
            189, 153, 80, 212, 148, 148, 20, 211, 140, 92, 32, 93, 14, 78, 196, 250, 7, 212, 137,
            232, 64, 80, 93, 246, 1, 210, 251, 250,
        ];
        let mut buffer = origin.clone();
        let header = vec![
            0, 184, 245, 226, 191, 127, 167, 243, 154, 198, 60, 245, 217, 172, 30, 129, 114,
        ];
        buffer.prepend_slice(&header);
        assert_eq!([header, origin].concat(), buffer);
    }

    #[cfg(feature = "bytes")]
    #[test]
    fn test_bytes_mut_prepend_to_empty_buffer() {
        use bytes::BytesMut;

        let header = [0, 1, 2, 3, 4];
        let buffer: alloc::vec::Vec<u8> = vec![];
        let mut buffer = BytesMut::from(&buffer[..]);
        buffer.prepend_slice(&header);
        assert_eq!(buffer, vec![0, 1, 2, 3, 4])
    }
    #[cfg(feature = "bytes")]
    #[test]
    fn test_bytes_mut_prepend_to_slice_smaller_buffer() {
        use bytes::BytesMut;

        let header = [0, 1, 2, 3, 4];
        let buffer: Vec<u8> = vec![5, 6];
        let mut buffer = BytesMut::from(&buffer[..]);
        buffer.prepend_slice(&header);
        assert_eq!(buffer, vec![0, 1, 2, 3, 4, 5, 6])
    }

    #[cfg(feature = "bytes")]
    #[test]
    fn test_bytes_mut_prepend_slice_to_slice() {
        use bytes::BytesMut;

        let header = [0, 1, 2, 3, 4];
        let buffer: Vec<u8> = vec![10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21];
        let mut buffer = BytesMut::from(&buffer[..]);

        buffer.prepend_slice(&header);
        assert_eq!(
            buffer,
            vec![0, 1, 2, 3, 4, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21]
        )
    }

    #[cfg(feature = "bytes")]
    #[test]
    fn test_bytes_mut_prepend_slice_explicit() {
        use bytes::BytesMut;

        let origin: Vec<u8> = vec![
            189, 153, 80, 212, 148, 148, 20, 211, 140, 92, 32, 93, 14, 78, 196, 250, 7, 212, 137,
            232, 64, 80, 93, 246, 1, 210, 251, 250,
        ];
        let mut buffer = BytesMut::from(&origin[..]);
        let header: Vec<u8> = vec![
            0, 184, 245, 226, 191, 127, 167, 243, 154, 198, 60, 245, 217, 172, 30, 129, 114,
        ];
        buffer.prepend_slice(&header);
        assert_eq!([header, origin].concat(), buffer);
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
