use std::io::Write;

use super::StreamEncryptor;

pub struct WriteAead<W>
where
    W: Write,
{
    encryptor: StreamEncryptor,
    writer: W,
}
