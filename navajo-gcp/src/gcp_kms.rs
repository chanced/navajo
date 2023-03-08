use base64::{engine::general_purpose::STANDARD_NO_PAD as b64, Engine as _};
use crc32c::crc32c;
use gcloud_sdk::google::cloud::kms::v1::key_management_service_client::KeyManagementServiceClient;
use gcloud_sdk::google::cloud::kms::v1::DecryptRequest;
use gcloud_sdk::proto_ext::kms::EncryptRequest;
use gcloud_sdk::*;
use navajo::Envelope;
use secret_vault_value::SecretValue;
use std::fmt::{Debug, Display};
use std::sync::Arc;
use tonic::metadata::MetadataValue;
use tonic::Status;

// TODO: Improve error handling, classify KmsError

#[derive(Debug)]
pub enum GcpKmsError {
    Tonic(Status),
    Base64(base64::DecodeError),
    Client(gcloud_sdk::error::Error),
}

impl std::error::Error for GcpKmsError {}
impl Display for GcpKmsError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            GcpKmsError::Tonic(e) => write!(f, "navajo-gcp: {e}"),
            GcpKmsError::Base64(e) => write!(f, "navajo-gcp: {e}"),
            GcpKmsError::Client(e) => write!(f, "navajo-gcp: {e}"),
        }
    }
}
impl From<Status> for GcpKmsError {
    fn from(status: Status) -> Self {
        Self::Tonic(status)
    }
}
impl From<base64::DecodeError> for GcpKmsError {
    fn from(err: base64::DecodeError) -> Self {
        Self::Base64(err)
    }
}
impl From<gcloud_sdk::error::Error> for GcpKmsError {
    fn from(err: gcloud_sdk::error::Error) -> Self {
        Self::Client(err)
    }
}

#[derive(Clone)]
pub struct GcpKms {
    client: Arc<tokio::sync::OnceCell<GoogleApi<KeyManagementServiceClient<GoogleAuthMiddleware>>>>,
}

impl GcpKms {
    pub fn new() -> Self {
        Self {
            client: Default::default(),
        }
    }
    pub fn key<N: ToString>(&self, name: N) -> GcpKmsKey {
        GcpKmsKey {
            name: name.to_string(),
            client: self.client.clone(),
        }
    }
}

impl Default for GcpKms {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Clone)]
pub struct GcpKmsKey {
    name: String,
    client: Arc<tokio::sync::OnceCell<GoogleApi<KeyManagementServiceClient<GoogleAuthMiddleware>>>>,
}
impl Debug for GcpKmsKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GcpKmsKey")
            .field("name", &self.name)
            .finish_non_exhaustive()
    }
}

impl GcpKmsKey {
    async fn try_get_client(
        &self,
    ) -> Result<KeyManagementServiceClient<GoogleAuthMiddleware>, GcpKmsError> {
        Ok(self.client.get_or_try_init(init_client).await?.get())
    }
}
impl Envelope for GcpKmsKey {
    type EncryptError = GcpKmsError;
    type DecryptError = GcpKmsError;

    fn encrypt_dek<A, P>(
        &self,
        aad: navajo::Aad<A>,
        plaintext: P,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<Vec<u8>, Self::EncryptError>> + Send + '_>,
    >
    where
        A: 'static + AsRef<[u8]> + Send + Sync,
        P: 'static + AsRef<[u8]> + Send + Sync,
    {
        let plaintext = b64.encode(plaintext.as_ref());
        let plaintext_crc32c = Some(crc32c(plaintext.as_bytes()) as i64);
        let plaintext = SecretValue::new(plaintext.as_bytes().to_vec());
        let additional_authenticated_data = aad.to_vec();
        let mut request = tonic::Request::new(EncryptRequest {
            name: self.name.clone(),
            plaintext,
            additional_authenticated_data,
            plaintext_crc32c,
            ..Default::default()
        });

        request.metadata_mut().insert(
            "x-goog-request-params",
            MetadataValue::<tonic::metadata::Ascii>::try_from(format!("name={}", self.name))
                .unwrap(),
        );
        Box::pin(async move {
            let response = self
                .try_get_client()
                .await?
                .encrypt(request)
                .await?
                .into_inner();
            Ok(response.ciphertext)
        })
    }

    fn decrypt_dek<A, C>(
        &self,
        aad: navajo::Aad<A>,
        ciphertext: C,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<Vec<u8>, Self::DecryptError>> + Send + '_>,
    >
    where
        A: 'static + AsRef<[u8]> + Send + Sync,
        C: 'static + AsRef<[u8]> + Send + Sync,
    {
        // let ciphertext = b64.encode(ciphertext.as_ref());
        let ciphertext_crc32c = Some(crc32c(ciphertext.as_ref()) as i64);

        let additional_authenticated_data = aad.to_vec();
        let mut request = tonic::Request::new(DecryptRequest {
            name: self.name.clone(),
            ciphertext: ciphertext.as_ref().to_vec(),
            additional_authenticated_data,
            ciphertext_crc32c,
            ..Default::default()
        });

        request.metadata_mut().insert(
            "x-goog-request-params",
            MetadataValue::<tonic::metadata::Ascii>::try_from(format!("name={}", self.name))
                .unwrap(),
        );
        Box::pin(async move {
            let response = self
                .try_get_client()
                .await?
                .decrypt(request)
                .await?
                .into_inner();
            let response = b64.decode(response.plaintext.as_sensitive_bytes())?;
            Ok(response)
        })
    }
}

async fn init_client(
) -> Result<GoogleApi<KeyManagementServiceClient<GoogleAuthMiddleware>>, gcloud_sdk::error::Error> {
    GoogleApi::from_function(
        KeyManagementServiceClient::new,
        "https://cloudkms.googleapis.com",
        None,
    )
    .await
}

pub mod sync {
    use super::Envelope;
    use std::sync::Arc;
    #[derive(Clone)]
    pub struct GcpKms {
        kms: Arc<super::GcpKms>,
        runtime: Arc<tokio::runtime::Runtime>,
    }

    impl GcpKms {
        pub fn new() -> Self {
            Self {
                kms: Arc::new(super::GcpKms::new()),
                runtime: Arc::new(tokio::runtime::Runtime::new().unwrap()),
            }
        }
        pub fn key<N: ToString>(&self, name: N) -> GcpKmsKey {
            GcpKmsKey {
                key: Arc::new(self.kms.key(name)),
                runtime: self.runtime.clone(),
            }
        }
    }

    impl Default for GcpKms {
        fn default() -> Self {
            Self::new()
        }
    }

    #[derive(Clone, Debug)]
    pub struct GcpKmsKey {
        key: Arc<super::GcpKmsKey>,
        runtime: Arc<tokio::runtime::Runtime>,
    }

    impl navajo::envelope::sync::Envelope for GcpKmsKey {
        type EncryptError = super::GcpKmsError;
        type DecryptError = super::GcpKmsError;

        fn encrypt_dek<A, P>(
            &self,
            aad: navajo::Aad<A>,
            plaintext: P,
        ) -> Result<Vec<u8>, Self::EncryptError>
        where
            A: AsRef<[u8]>,
            P: AsRef<[u8]>,
        {
            let aad = navajo::Aad(aad.as_ref().to_vec());
            let cleartext = plaintext.as_ref().to_vec();
            self.runtime
                .block_on(async move { self.key.encrypt_dek(aad, cleartext).await })
        }

        fn decrypt_dek<A, C>(
            &self,
            aad: navajo::Aad<A>,
            ciphertext: C,
        ) -> Result<Vec<u8>, Self::DecryptError>
        where
            A: AsRef<[u8]>,
            C: AsRef<[u8]>,
        {
            let aad = navajo::Aad(aad.as_ref().to_vec());
            let ciphertext = ciphertext.as_ref().to_vec();
            self.runtime
                .block_on(async move { self.key.decrypt_dek(aad, ciphertext).await })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_encrypt() {
        // todo: need to figure out how to safely run this in CI
        let gcp = GcpKms::new();
        let key = gcp.key(std::env::var("GCP_KMS_KEY_URI").unwrap());
        let aad = navajo::Aad("test");
        let plaintext = "test";
        let ciphertext = key.encrypt_dek(aad, plaintext).await.unwrap();
        let plaintext = key.decrypt_dek(aad, ciphertext.clone()).await.unwrap();

        println!("{ciphertext:?}");
        println!("{}", String::from_utf8(plaintext).unwrap());
    }
}
