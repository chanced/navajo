use super::StreamEncryptor;
#[cfg(feature = "std")]
pub struct WriteAead<W>
where
    W: std::io::Write,
{
    encryptor: StreamEncryptor,
    writer: W,
}
