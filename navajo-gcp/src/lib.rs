use std::pin::Pin;

use kms_aead::{CipherText, KmsAeadEnvelopeEncryption, KmsAeadRingEnvelopeEncryption};
use secret_vault_value::SecretValue;

pub struct GcpKms {
    key: KmsAeadRingEnvelopeEncryption<kms_aead::providers::GcpKmsProvider>,
}

impl navajo::Envelope for GcpKms {
    type EncryptError = kms_aead::errors::KmsAeadError;
    type DecryptError = kms_aead::errors::KmsAeadError;

    fn encrypt_dek<'a, A, P>(
        &'a self,
        aad: navajo::Aad<A>,
        cleartext: P,
    ) -> Pin<Box<dyn std::future::Future<Output = Result<Vec<u8>, Self::EncryptError>> + Send + '_>>
    where
        A: 'static + AsRef<[u8]> + Send + Sync,
        P: 'static + AsRef<[u8]> + Send + Sync,
    {
        Box::pin(async move {
            let secret_value = SecretValue::new(cleartext.as_ref().to_vec());
            let res = self.key.encrypt_value(&aad, &secret_value).await?;
            Ok(res.value().to_vec())
        })
    }

    fn encrypt_dek_sync<A, P>(
        &self,
        aad: navajo::Aad<A>,
        cleartext: P,
    ) -> Result<Vec<u8>, Self::EncryptError>
    where
        A: AsRef<[u8]>,
        P: AsRef<[u8]>,
    {
        use tokio::runtime::Builder;
        let runtime = Builder::new_current_thread().enable_all().build().unwrap();
        let aad = navajo::Aad(aad.as_ref().to_vec());
        let cleartext = cleartext.as_ref().to_vec();
        runtime.block_on(async move { self.encrypt_dek(aad, cleartext).await })
    }

    fn decrypt_dek<'a, A, C>(
        &'a self,
        aad: navajo::Aad<A>,
        ciphertext: C,
    ) -> Pin<Box<dyn std::future::Future<Output = Result<Vec<u8>, Self::DecryptError>> + Send + '_>>
    where
        A: 'static + AsRef<[u8]> + Send + Sync,
        C: 'static + AsRef<[u8]> + Send + Sync,
    {
        Box::pin(async move {
            let c: CipherText = CipherText(ciphertext.as_ref().to_vec());
            let res = self.key.decrypt_value_with_current_key(&aad, &c).await?;
            Ok(res.0.ref_sensitive_value().clone())
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
        let runtime = Builder::new_current_thread().enable_all().build().unwrap();
        let aad = navajo::Aad(aad.as_ref().to_vec());
        let ciphertext = ciphertext.as_ref().to_vec();
        runtime.block_on(async move { self.decrypt_dek(aad, ciphertext).await })
    }
}
