use navajo::{primitive::Primitive, Aad};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[derive(Clone, Debug)]
pub enum Envelope {
    Cleartext(navajo::PlaintextJson),
    Gcp(navajo_gcp::CryptoKey),
}
impl Envelope {
    pub async fn open<A>(
        &self,
        aad: Aad<A>,
        mut read: Box<dyn tokio::io::AsyncRead + Unpin>,
    ) -> Result<Primitive, Box<dyn std::error::Error>>
    where
        A: 'static + AsRef<[u8]> + Send + Sync,
    {
        let mut data = Vec::new();
        read.read_to_end(&mut data).await?;
        match self {
            Envelope::Cleartext(envelope) => Ok(Primitive::open(aad, data, envelope).await?),
            Envelope::Gcp(envelope) => Ok(Primitive::open(aad, data, envelope).await?),
        }
    }
    pub async fn seal_and_write<A>(
        &self,
        mut write: Box<dyn tokio::io::AsyncWrite + Unpin>,
        aad: Aad<A>,
        primitive: Primitive,
    ) -> Result<(), Box<dyn std::error::Error>>
    where
        A: 'static + AsRef<[u8]> + Send + Sync,
    {
        let sealed = match self {
            Envelope::Cleartext(envelope) => primitive.seal(aad, envelope).await?,
            Envelope::Gcp(envelope) => primitive.seal(aad, envelope).await?,
        };
        write.write_all(&sealed).await?;
        write.flush().await?;
        Ok(())
    }
}
