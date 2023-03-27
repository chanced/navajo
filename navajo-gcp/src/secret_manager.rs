use gcloud_sdk::{
    google::cloud::secretmanager::v1::{
        secret_manager_service_client::SecretManagerServiceClient, AccessSecretVersionRequest,
        GetSecretRequest,
    },
    GoogleApi, GoogleAuthMiddleware,
};
use navajo::{secret_store::SecretStore, sensitive};
use secret_vault_value::SecretValue;
use std::{fmt::Display, sync::Arc};
use tokio::sync::OnceCell;
use tonic::{Request, Status};

#[derive(Clone)]
pub struct SecretManager {
    client: Arc<OnceCell<GoogleApi<SecretManagerServiceClient<GoogleAuthMiddleware>>>>,
}

impl SecretManager {
    /// Creates a new SecretManager instance.
    pub fn new() -> Self {
        Self {
            client: Default::default(),
        }
    }

    /// Attempts to retrieve the Secret from GCP. The name must be in the format:
    /// ```plaintext
    /// projects/*/secrets/*
    /// ```
    ///
    /// # Errors
    /// Returns a `SecretManagerError` if the Secret cannot be retrieved from GCP.
    ///
    /// # Example
    /// ```no_run
    /// use navajo_gcp::SecretManager;
    ///
    /// #[tokio::main]
    /// async fn main() {
    ///     let secret_manager = SecretManager::new();
    ///     let secret = secret_manager.secret("my-secret").await.unwrap();
    ///     let secret_version = secret.latest().await.unwrap();
    ///     let secret_value = secret_version.value();
    /// }
    ///
    pub async fn secret<N: ToString>(&self, name: N) -> Result<Secret, SecretManagerError> {
        let name = name.to_string();
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

impl Default for SecretManager {
    fn default() -> Self {
        Self::new()
    }
}

impl SecretStore for SecretManager {
    type Error = SecretManagerError;
    fn get_secret<N: ToString>(
        &self,
        name: N,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<sensitive::Bytes, Self::Error>> + Send + '_>,
    > {
        let mut name = name.to_string();
        let parts: Vec<String> = name.split('/').map(|s| s.to_string()).collect();
        let mut version = "latest".to_string();
        if parts.len() > 4 {
            name = parts[..4].join("/");
            if parts.len() > 5 {
                version = parts[5].clone();
            }
        }
        Box::pin(async move {
            let secret = self.secret(name).await?;
            let secret_version = secret.version(version).await?;
            Ok(sensitive::Bytes::new(
                secret_version
                    .value()
                    .map(|v| v.as_sensitive_bytes())
                    .unwrap_or(&[]),
            ))
        })
    }
}

pub mod sync {
    use std::sync::Arc;

    use navajo::secret_store::{sync::SecretStore, SecretStore as _};

    pub struct SecretManager {
        inner: super::SecretManager,
        runtime: Arc<tokio::runtime::Runtime>,
    }
    impl SecretManager {
        pub fn new() -> Self {
            Self {
                inner: super::SecretManager::new(),
                runtime: Arc::new(tokio::runtime::Runtime::new().unwrap()),
            }
        }
    }
    impl SecretStore for SecretManager {
        type Error = super::SecretManagerError;
        fn get<N: ToString>(&self, name: N) -> Result<navajo::sensitive::Bytes, Self::Error> {
            self.runtime.block_on(self.inner.get_secret(name))
        }
    }
    impl Default for SecretManager {
        fn default() -> Self {
            Self::new()
        }
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
    /// ```no_run
    /// use navajo_gcp::SecretManager;
    ///
    /// #[tokio::main]
    /// async fn main() {
    ///     let secret_manager = SecretManager::new();
    ///     let secret = secret_manager.secret("projects/my-project/secrets/my-secret").await.unwrap();
    ///     let secret_version = secret.version("latest").await.unwrap();
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
    use super::SecretStore;
    use super::*;
    #[tokio::test]
    #[ignore]
    async fn test_get_secret_version() {
        let _project_id = std::env::var("PROJECT_ID").unwrap();
        let secret_manager = SecretManager::new();
        let secret = secret_manager.secret("test-secret").await.unwrap();
        let secret_version = secret.latest().await.unwrap();
        println!("{secret_version:?}")
    }
    #[tokio::test]
    #[ignore]
    async fn test_secret_store() {
        let project_id = std::env::var("PROJECT_ID").unwrap();
        let secret_name = format!("projects/{project_id}/secrets/test-secret2/version/1");
        let secret_manager = SecretManager::new();
        let secret = secret_manager.get_secret(secret_name).await.unwrap();
        println!("{:?}", String::from_utf8_lossy(secret.as_ref()))
    }
}
