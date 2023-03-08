use std::fmt::Display;

use gcloud_sdk::{
    google::cloud::secretmanager::v1::secret_manager_service_client::SecretManagerServiceClient,
    GoogleApi, GoogleAuthMiddleware,
};


#[derive(Debug, Clone)]
pub enum SecretStoreError {}
impl Display for SecretStoreError {
    fn fmt(&self, _f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        todo!()
    }
}
impl std::error::Error for SecretStoreError {}

pub struct GcpSecretStore {
    client: GoogleApi<SecretManagerServiceClient<GoogleAuthMiddleware>>,
}

impl GcpSecretStore {
    pub async fn new<N>(_name: N) -> Result<Self, gcloud_sdk::error::Error>
    where
        N: ToString,
    {
        let client: GoogleApi<SecretManagerServiceClient<GoogleAuthMiddleware>> =
            GoogleApi::from_function(
                SecretManagerServiceClient::new,
                "https://secretmanager.googleapis.com",
                // cloud resource prefix: used only for some of the APIs (such as Firestore)
                None,
            )
            .await?;

        Ok(Self { client })
    }
}
