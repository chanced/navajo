use std::io::Write;

use super::{Buffer, Encryptor};
#[cfg(feature = "std")]
pub struct EncryptWriter<W, B>
where
    W: Write,
    B: Buffer,
{
    encryptor: Encryptor<B>,
    writer: W,
}
