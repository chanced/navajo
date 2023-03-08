use gcloud_sdk::{
    google::cloud::secretmanager::v1::{
        secret, secret_manager_service_client::SecretManagerServiceClient,
        AccessSecretVersionRequest, AccessSecretVersionResponse, GetSecretRequest,
    },
    GoogleApi, GoogleAuthMiddleware,
};
use navajo::sensitive;
use secret_vault_value::SecretValue;
use std::{fmt::Display, ops::Deref, sync::Arc};
use tokio::sync::OnceCell;
use tonic::{Request, Status};

#[derive(Clone)]
pub struct SecretManager {
    client: Arc<OnceCell<GoogleApi<SecretManagerServiceClient<GoogleAuthMiddleware>>>>,
    project_id: String,
}

impl SecretManager {
    /// Creates a new SecretManager instance.
    pub fn new<N: ToString>(project_id: N) -> Self {
        Self {
            project_id: project_id.to_string(),
            client: Default::default(),
        }
    }
    pub fn project_id(&self) -> &str {
        &self.project_id
    }

    /// Attempts to retrieve the Secret from GCP.
    ///
    /// # Errors
    /// Returns a `SecretManagerError` if the Secret cannot be retrieved from GCP.
    ///
    /// # Example
    /// ```
    /// use navajo_gcp::gcp_secret_manager::SecretManager;
    ///
    /// #[tokio::main]
    /// async fn main() {
    ///     let secret_manager = SecretManager::new("my-project");
    ///     let secret = secret_manager.secret("my-secret").await?;
    ///     let secret_version = secret.latest().await?;
    ///     let secret_value = secret_version.value();
    /// }
    ///
    pub async fn secret<N: ToString>(&self, name: N) -> Result<Secret, SecretManagerError> {
        let name = name.to_string();
        let name = format!("projects/{}/secrets/{name}", self.project_id());
        let secret = self
            .try_get_client()
            .await?
            .get_secret(Request::new(GetSecretRequest { name }))
            .await?
            .into_inner();
        Ok(Secret {
            inner: secret,

            client: self.client.clone(),
        })
    }
    async fn try_get_client(
        &self,
    ) -> Result<SecretManagerServiceClient<GoogleAuthMiddleware>, SecretManagerError> {
        Ok(self.client.get_or_try_init(init_client).await?.get())
    }
}

#[derive(Clone)]
pub struct Secret {
    inner: gcloud_sdk::google::cloud::secretmanager::v1::Secret,
    client: Arc<OnceCell<GoogleApi<SecretManagerServiceClient<GoogleAuthMiddleware>>>>,
}
impl Secret {
    pub async fn latest(&self) -> Result<SecretVersion, SecretManagerError> {
        self.version("latest").await
    }

    /// # Example
    /// ```
    /// use navajo_gcp::gcp_secret_manager::SecretManager;
    ///
    /// #[tokio::main]
    /// async fn main() {
    ///     let secret_manager = SecretManager::new("my-project");
    ///     let secret = secret_manager.secret("my-secret").await?;
    ///     let secret_version = secret.version("latest").await?;
    ///     let secret_value = secret_version.value();
    /// }
    ///
    pub async fn version<N: ToString>(&self, name: N) -> Result<SecretVersion, SecretManagerError> {
        let secret_version = self
            .try_get_client()
            .await?
            .access_secret_version(Request::new(AccessSecretVersionRequest {
                name: format!("{}/versions/{}", self.inner.name, name.to_string()),
            }))
            .await?
            .into_inner();
        Ok(SecretVersion {
            name: secret_version.name,
            value: secret_version.payload.map(|p| p.data),
        })
    }
    async fn try_get_client(
        &self,
    ) -> Result<SecretManagerServiceClient<GoogleAuthMiddleware>, SecretManagerError> {
        Ok(self.client.get_or_try_init(init_client).await?.get())
    }
}

#[derive(Clone, Debug)]
pub struct SecretVersion {
    name: String, // todo: this should probably be parsed as an u64. leaving for now
    value: Option<SecretValue>,
}

impl SecretVersion {
    pub fn value(&self) -> Option<&SecretValue> {
        self.value.as_ref()
    }
    pub fn name(&self) -> &str {
        &self.name
    }
}
async fn init_client(
) -> Result<GoogleApi<SecretManagerServiceClient<GoogleAuthMiddleware>>, gcloud_sdk::error::Error> {
    GoogleApi::from_function(
        SecretManagerServiceClient::new,
        "https://secretmanager.googleapis.com",
        None,
    )
    .await
}

// TODO: Improve error handling, classify KmsError

#[derive(Debug)]
pub enum SecretManagerError {
    Tonic(Status),
    Client(gcloud_sdk::error::Error),
}

impl std::error::Error for SecretManagerError {}
impl Display for SecretManagerError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SecretManagerError::Tonic(e) => write!(f, "navajo-gcp: {e}"),
            SecretManagerError::Client(e) => write!(f, "navajo-gcp: {e}"),
        }
    }
}

impl From<Status> for SecretManagerError {
    fn from(status: Status) -> Self {
        Self::Tonic(status)
    }
}
impl From<gcloud_sdk::error::Error> for SecretManagerError {
    fn from(err: gcloud_sdk::error::Error) -> Self {
        Self::Client(err)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_get_secret_version() {
        let secret_manager = SecretManager::new(std::env::var("PROJECT_ID").unwrap());
        let secret = secret_manager.secret("test-secret").await.unwrap();
        let secret_version = secret.latest().await.unwrap();
        println!("{secret_version:?}")
    }
}
