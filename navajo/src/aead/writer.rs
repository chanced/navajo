use super::{Buffer, Encrypt};
#[cfg(feature = "std")]
pub struct WriteAead<W, B>
where
    W: std::io::Write,
    B: Buffer,
{
    encryptor: Encrypt<B>,
    writer: W,
}
