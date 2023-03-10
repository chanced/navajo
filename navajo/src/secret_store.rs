use core::pin::Pin;

use futures::Future;

use crate::{error::Error, sensitive};

pub trait SecretStore {
    type Error: Error + Send + Sync;
    fn get<N: ToString>(
        &self,
        name: N,
    ) -> Pin<Box<dyn Future<Output = Result<sensitive::Bytes, Self::Error>> + Send + '_>>;
}

pub mod sync {
    use crate::{error::Error, sensitive};
    pub trait SecretStore {
        type Error: Error + Send + Sync;
        fn get<N: ToString>(&self, name: N) -> Result<sensitive::Bytes, Self::Error>;
    }
}
