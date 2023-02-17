use super::{Buffer, Encryptor};
#[cfg(feature = "std")]
pub struct WriteAead<W, B>
where
    W: std::io::Write,
    B: Buffer,
{
    encryptor: Encryptor<B>,
    writer: W,
}
