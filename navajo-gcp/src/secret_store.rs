use navajo::secret_store::SecretStore;

pub enum SecretStoreError {}

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
