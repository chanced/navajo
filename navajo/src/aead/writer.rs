use super::StreamingEncrypt;
#[cfg(feature = "std")]
pub struct WriteAead<W>
where
    W: std::io::Write,
{
    encryptor: StreamingEncrypt,
    writer: W,
}
