use std::fmt::Display;

use navajo::secret_store::SecretStore;

#[derive(Debug, Clone)]
pub enum SecretStoreError {}
impl Display for SecretStoreError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        todo!()
    }
}
impl std::error::Error for SecretStoreError {}

pub struct GcpSecretStore {}
impl SecretStore for GcpSecretStore {
    type Error = SecretStoreError;

    fn get<N: ToString>(
        &self,
        name: N,
    ) -> std::pin::Pin<
        Box<
            dyn std::future::Future<Output = Result<navajo::sensitive::Bytes, Self::Error>>
                + Send
                + '_,
        >,
    > {
        todo!()
    }

    fn get_sync<N: ToString>(&self, name: N) -> Result<navajo::sensitive::Bytes, Self::Error> {
        todo!()
    }
}
