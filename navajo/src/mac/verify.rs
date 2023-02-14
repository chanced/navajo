use futures::{Stream, TryStream};

use crate::error::MacVerificationError;

use super::{compute::Compute, Mac, Tag, VerifyStream, VerifyTryStream};

pub struct Verify<T>
where
    T: AsRef<Tag> + Send + Sync,
{
    tag: T,
    hasher: Compute,
}
impl<T> Verify<T>
where
    T: AsRef<Tag> + Send + Sync,
{
    pub(super) fn new(tag: T, mac: &Mac) -> Self {
        let _t = tag.as_ref();
        let hasher = Compute::new(mac);
        Self { tag, hasher }
    }
    pub fn update(&mut self, data: &[u8]) {
        self.hasher.update(data)
    }

    pub fn stream<S, D>(self, stream: S) -> VerifyStream<S, D, T>
    where
        D: AsRef<[u8]>,
        S: Stream<Item = D>,
    {
        VerifyStream::new(stream, self)
    }
    pub fn try_stream<S, D, E>(self, stream: S) -> VerifyTryStream<S, S::Ok, S::Error, T>
    where
        D: AsRef<[u8]>,
        E: Send + Sync,
        S: TryStream<Ok = D, Error = E>,
    {
        VerifyTryStream::new(stream, self)
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

#[cfg(feature = "std")]
impl<T> std::io::Write for Verify<T>
where
    T: AsRef<Tag> + Send + Sync,
{
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.update(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}
