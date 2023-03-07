use core::{fmt::Display, pin::Pin};

use futures::Future;

use crate::sensitive;

pub trait SecretStore {
    type Error: Display + Send + Sync;
    fn get<N: ToString>(
        &self,
        name: N,
    ) -> Pin<Box<dyn Future<Output = Result<sensitive::Bytes, Self::Error>> + Send + '_>>;
    fn get_sync<N: ToString>(&self, name: N) -> Result<sensitive::Bytes, Self::Error>;
}
