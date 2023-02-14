use alloc::vec::Vec;
use bytes::BytesMut;
use rust_crypto_aead::Buffer as RustCryptoBuffer;
pub trait Buffer: AsRef<[u8]> + AsMut<[u8]> + for<'a> Extend<&'a u8> {
    fn truncate(&mut self, len: usize);
}

impl Buffer for Vec<u8> {
    fn truncate(&mut self, len: usize) {
        self.truncate(len)
    }
}

impl Buffer for BytesMut {
    fn truncate(&mut self, len: usize) {
        self.truncate(len)
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

    use super::prepend_to_buffer;

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
}
