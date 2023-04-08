use futures::{Stream, TryStream};

use crate::error::MacVerificationError;

use super::{computer::Computer, Mac, Tag, VerifyStream, VerifyTryStream};

pub struct Verifier<T>
where
    T: AsRef<Tag>,
{
    tag: T,
    hasher: Computer,
}
impl<T> Verifier<T>
where
    T: AsRef<Tag>,
{
    pub(super) fn new(tag: T, mac: &Mac) -> Self {
        let hasher = Computer::new(mac);
        Self { tag, hasher }
    }
    pub fn update(&mut self, data: &[u8]) {
        self.hasher.update(data)
    }

    pub fn finalize(self) -> Result<Tag, MacVerificationError> {
        let computed = self.hasher.finalize();
        if self.tag.as_ref() == computed {
            Ok(computed)
        } else {
            Err(MacVerificationError)
        }
    }
}
impl<T> Verifier<T>
where
    T: AsRef<Tag> + Send + Sync,
{
    pub fn stream<S>(self, stream: S) -> VerifyStream<S, T>
    where
        S: Stream,
        S::Item: AsRef<[u8]>,
    {
        VerifyStream::new(stream, self)
    }
    pub fn try_stream<S, D, E>(self, stream: S) -> VerifyTryStream<S, T>
    where
        D: AsRef<[u8]>,
        E: Send + Sync,
        S: TryStream<Ok = D, Error = E>,
    {
        VerifyTryStream::new(stream, self)
    }
}

#[cfg(feature = "std")]
impl<T> std::io::Write for Verifier<T>
where
    T: AsRef<Tag>,
{
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.update(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}
