use base64::{engine::general_purpose::STANDARD_NO_PAD as b64, Engine as _};
use crc32c::crc32c;
use gcloud_sdk::google::cloud::kms::v1::key_management_service_client::KeyManagementServiceClient;
use gcloud_sdk::google::cloud::kms::v1::DecryptRequest;
use gcloud_sdk::proto_ext::kms::EncryptRequest;
use gcloud_sdk::*;
use navajo::Envelope;
use secret_vault_value::SecretValue;
use std::fmt::Display;
use tonic::metadata::MetadataValue;
use tonic::Status;
#[derive(Clone, Debug)]
pub enum KmsError {
    Tonic(Status),
    Base64(base64::DecodeError),
}
impl std::error::Error for KmsError {}
impl Display for KmsError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            KmsError::Tonic(e) => write!(f, "navajo-gcp: {e}"),
            KmsError::Base64(e) => write!(f, "navajo-gcp: {e}"),
        }
    }
}
impl From<Status> for KmsError {
    fn from(status: Status) -> Self {
        Self::Tonic(status)
    }
}
impl From<base64::DecodeError> for KmsError {
    fn from(err: base64::DecodeError) -> Self {
        Self::Base64(err)
    }
}
pub struct GcpKms {
    pub name: String,
    client: GoogleApi<KeyManagementServiceClient<GoogleAuthMiddleware>>,
}

impl GcpKms {
    /// key_uri is a URI of the form:
    /// ```plaintext
    /// projects/*/locations/*/keyRings/*/cryptoKeys/*
    /// ```
    pub async fn new(name: impl ToString) -> Result<Self, gcloud_sdk::error::Error> {
        let client: GoogleApi<KeyManagementServiceClient<GoogleAuthMiddleware>> =
            GoogleApi::from_function(
                KeyManagementServiceClient::new,
                "https://cloudkms.googleapis.com",
                None,
            )
            .await?;

        Ok(Self {
            name: name.to_string(),
            client,
        })
    }
}
impl Envelope for GcpKms {
    type EncryptError = KmsError;
    type DecryptError = KmsError;

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
            let response = self.client.get().encrypt(request).await?.into_inner();

            Ok(response.ciphertext)
        })
    }

    fn encrypt_dek_sync<A, P>(
        &self,
        aad: navajo::Aad<A>,
        plaintext: P,
    ) -> Result<Vec<u8>, Self::EncryptError>
    where
        A: AsRef<[u8]>,
        P: AsRef<[u8]>,
    {
        use tokio::runtime::Builder;
        let runtime = Builder::new_current_thread().enable_io().build().unwrap();
        let aad = navajo::Aad(aad.as_ref().to_vec());
        let cleartext = plaintext.as_ref().to_vec();
        runtime.block_on(async move { self.encrypt_dek(aad, cleartext).await })
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
            let response = self.client.get().decrypt(request).await?.into_inner();
            let response = b64.decode(response.plaintext.as_sensitive_bytes())?;
            Ok(response)
        })
    }

    fn decrypt_dek_sync<A, C>(
        &self,
        aad: navajo::Aad<A>,
        ciphertext: C,
    ) -> Result<Vec<u8>, Self::DecryptError>
    where
        A: AsRef<[u8]>,
        C: AsRef<[u8]>,
    {
        use tokio::runtime::Builder;
        let runtime = Builder::new_current_thread().enable_io().build().unwrap();
        let aad = navajo::Aad(aad.as_ref().to_vec());
        let ciphertext = ciphertext.as_ref().to_vec();
        runtime.block_on(async move { self.decrypt_dek(aad, ciphertext).await })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_encrypt() {
        // todo: need to figure out how to safely run this in CI
        let gcp = super::GcpKms::new(std::env::var("GCP_KMS_KEY_URI").unwrap())
            .await
            .unwrap();
        let aad = navajo::Aad("test");
        let plaintext = "test";
        let ciphertext = gcp.encrypt_dek(aad, plaintext).await.unwrap();
        let plaintext = gcp.decrypt_dek(aad, ciphertext.clone()).await.unwrap();

        println!("{ciphertext:?}");
        println!("{}", String::from_utf8(plaintext).unwrap());
    }
}
