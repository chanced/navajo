mod keyring_info;
mod kind;
pub use keyring_info::KeyringInfo;
pub use kind::Kind;

use crate::{
    envelope::{self, is_plaintext},
    error::{OpenError, SealError},
    keyring::Keyring,
    Aad,
    Envelope,
    // mac, signature, Aad, Daead, Envelope, Mac, Signer,
};
use aes_gcm::aead::AeadInPlace;
use aes_gcm::Aes256Gcm;
use alloc::{string::ToString, vec::Vec};
use rust_crypto_aead::AeadCore;
use rust_crypto_aead::KeyInit;
use serde::{Deserialize, Serialize};
use serde_json::Value;

const AES_256_GCM_KEY_SIZE: usize = 32;
const AES_256_GCM_NONCE_SIZE: usize = 12;
const AES_256_GCM_TAG_SIZE: usize = 16;

pub enum Primitive {
    #[cfg(feature = "aead")]
    Aead(crate::Aead),
    #[cfg(feature = "daead")]
    Daead(crate::Daead),
    // Hpke(Hpke) // TODO: Enable this when HPKE is implemented
    #[cfg(feature = "mac")]
    Mac(crate::Mac),
    #[cfg(feature = "dsa")]
    Dsa(crate::Signer),
}
impl Primitive {
    pub async fn seal<A, E>(&self, aad: Aad<A>, envelope: &E) -> Result<Vec<u8>, SealError>
    where
        A: 'static + AsRef<[u8]> + Send + Sync,
        E: 'static + Envelope,
    {
        if is_plaintext(envelope) {
            return self.serialize_keyring();
        }
        let serialized_keyring = self.serialize_keyring()?;
        let encrypted_keyring = encrypt_keyring_data(aad, serialized_keyring)?;
        seal_keyring_data(envelope, encrypted_keyring).await
    }

    pub fn seal_sync<'a, A, E>(&'a self, aad: Aad<A>, envelope: &'a E) -> Result<Vec<u8>, SealError>
    where
        A: AsRef<[u8]>,
        E: 'static + envelope::sync::Envelope,
    {
        if is_plaintext(envelope) {
            return self.serialize_keyring();
        }
        let serialized_keyring = self.serialize_keyring()?;
        let encrypted_keyring = encrypt_keyring_data(aad, serialized_keyring)?;
        seal_keyring_data_sync(envelope, encrypted_keyring)
    }

    pub async fn open<A, C, E>(aad: Aad<A>, ciphertext: C, envelope: &E) -> Result<Self, OpenError>
    where
        A: AsRef<[u8]> + Send + Sync,
        C: AsRef<[u8]> + Send + Sync,
        E: 'static + Envelope,
    {
        let ciphertext = ciphertext.as_ref();
        if ciphertext.is_empty() {
            return Err("keyring data is empty".into());
        }
        if is_plaintext(envelope) {
            return Self::deserialize_keyring(ciphertext);
        }
        let ciphertext = read_encrypted(ciphertext)?;
        let sealed_cipher_and_nonce = read_sealed_cipher_and_nonce(&ciphertext)?;

        let key = envelope
            .decrypt_dek(Aad(aad.as_ref().to_vec()), sealed_cipher_and_nonce.clone())
            .await
            .map_err(|e| e.to_string())?;

        let data = open_keyring_data(key, aad, &ciphertext, &sealed_cipher_and_nonce)?;
        let PrimitiveData { kind, keys } = serde_json::from_slice(&data)?;

        Self::open_value(kind, keys)
    }

    pub fn open_sync<A, C, E>(aad: Aad<A>, ciphertext: C, envelope: &E) -> Result<Self, OpenError>
    where
        A: AsRef<[u8]>,
        C: AsRef<[u8]>,
        E: 'static + crate::envelope::sync::Envelope,
    {
        let ciphertext = ciphertext.as_ref();
        if ciphertext.is_empty() {
            return Err("sealed data is empty".into());
        }
        if is_plaintext(envelope) {
            Self::deserialize_keyring(ciphertext)
        } else {
            let ciphertext = read_encrypted(ciphertext)?;

            let sealed_cipher_and_nonce = read_sealed_cipher_and_nonce(&ciphertext)?;
            let key = envelope
                .decrypt_dek(Aad(aad.as_ref()), sealed_cipher_and_nonce.clone())
                .map_err(|e| e.to_string())?;
            let data = open_keyring_data(key, aad, &ciphertext, &sealed_cipher_and_nonce)?;

            let PrimitiveData { kind, keys } = serde_json::from_slice(&data)?;

            Self::open_value(kind, keys)
        }
    }

    fn open_value(kind: Kind, value: Value) -> Result<Self, OpenError> {
        match kind {
            Kind::Aead => {
                #[cfg(feature = "aead")]
                {
                    let keyring: Keyring<crate::aead::Material> = serde_json::from_value(value)?;
                    Ok(Self::Aead(crate::Aead::from_keyring(keyring)))
                }
                #[cfg(not(feature = "aead"))]
                {
                    Err("aead feature is not enabled".into())
                }
            }
            Kind::Daead => {
                #[cfg(feature = "daead")]
                {
                    let keyring: Keyring<crate::daead::Material> = serde_json::from_value(value)?;
                    Ok(Self::Daead(crate::Daead::from_keyring(keyring)))
                }
                #[cfg(not(feature = "daead"))]
                {
                    Err("daead feature is not enabled".into())
                }
            }
            Kind::Mac => {
                #[cfg(feature = "mac")]
                {
                    let keyring: Keyring<crate::mac::Material> = serde_json::from_value(value)?;
                    Ok(Self::Mac(crate::Mac::from_keyring(keyring)))
                }
                #[cfg(not(feature = "mac"))]
                {
                    Err("mac feature is not enabled".into())
                }
            }
            Kind::Dsa => {
                #[cfg(feature = "dsa")]
                {
                    let keyring: Keyring<crate::dsa::Material> = serde_json::from_value(value)?;
                    Ok(Self::Dsa(crate::Signer::from_keyring(keyring)))
                }
                #[cfg(not(feature = "dsa"))]
                {
                    Err("signature feature is not enabled".into())
                }
            }
        }
    }
    pub fn kind(&self) -> Kind {
        match self {
            #[cfg(feature = "aead")]
            Primitive::Aead(_) => Kind::Aead,
            #[cfg(feature = "daead")]
            Primitive::Daead(_) => Kind::Daead,
            #[cfg(feature = "mac")]
            Primitive::Mac(_) => Kind::Mac,
            #[cfg(feature = "dsa")]
            Primitive::Dsa(_) => Kind::Dsa,
        }
    }

    pub fn info(&self) -> KeyringInfo {
        self.into()
    }

    #[cfg(feature = "aead")]
    pub fn aead(self) -> Option<crate::Aead> {
        match self {
            Primitive::Aead(aead) => Some(aead),
            _ => None,
        }
    }
    #[cfg(feature = "daead")]
    pub fn daead(self) -> Option<crate::Daead> {
        match self {
            Primitive::Daead(daead) => Some(daead),
            _ => None,
        }
    }
    #[cfg(feature = "mac")]
    pub fn mac(self) -> Option<crate::Mac> {
        match self {
            Primitive::Mac(mac) => Some(mac),
            _ => None,
        }
    }
    #[cfg(feature = "dsa")]
    pub fn signer(self) -> Option<crate::Signer> {
        match self {
            Primitive::Dsa(sig) => Some(sig),
            _ => None,
        }
    }
    fn deserialize_keyring(value: &[u8]) -> Result<Self, OpenError> {
        let data: PrimitiveData = serde_json::from_slice(value)?;
        match data.kind {
            Kind::Aead => {
                #[cfg(feature = "aead")]
                {
                    let keyring: Keyring<crate::aead::Material> =
                        serde_json::from_value(data.keys)?;
                    Ok(Primitive::Aead(crate::Aead::from_keyring(keyring)))
                }
                #[cfg(not(feature = "aead"))]
                {
                    Err("aead feature is not enabled".into())
                }
            }
            Kind::Daead => {
                #[cfg(feature = "daead")]
                {
                    let keyring: Keyring<crate::daead::Material> =
                        serde_json::from_value(data.keys)?;
                    Ok(Primitive::Daead(crate::Daead::from_keyring(keyring)))
                }
                #[cfg(not(feature = "daead"))]
                {
                    Err("daead feature is not enabled".into())
                }
            }
            Kind::Mac => {
                #[cfg(feature = "mac")]
                {
                    let keyring: Keyring<crate::mac::Material> = serde_json::from_value(data.keys)?;
                    Ok(Primitive::Mac(crate::Mac::from_keyring(keyring)))
                }
                #[cfg(not(feature = "mac"))]
                {
                    Err("mac feature is not enabled".into())
                }
            }
            Kind::Dsa => {
                #[cfg(feature = "dsa")]
                {
                    let keyring: Keyring<crate::dsa::Material> = serde_json::from_value(data.keys)?;
                    Ok(Primitive::Dsa(crate::Signer::from_keyring(keyring)))
                }
                #[cfg(not(feature = "dsa"))]
                {
                    Err("signature feature is not enabled".into())
                }
            }
        }
    }

    fn serialize_keyring(&self) -> Result<Vec<u8>, SealError> {
        let keyring = match self {
            #[cfg(feature = "aead")]
            Primitive::Aead(aead) => serde_json::to_value(aead.keyring())?,
            #[cfg(feature = "daead")]
            Primitive::Daead(daead) => serde_json::to_value(daead.keyring())?,
            #[cfg(feature = "mac")]
            Primitive::Mac(mac) => serde_json::to_value(mac.keyring())?,
            #[cfg(feature = "dsa")]
            Primitive::Dsa(sig) => serde_json::to_value(sig.keyring())?,
        };
        let data = PrimitiveData {
            kind: self.kind(),
            keys: keyring,
        };
        serde_json::to_vec(&data).map_err(|e| SealError(e.to_string()))
    }
}

#[derive(Serialize, Deserialize)]
struct PrimitiveData {
    #[serde(rename = "kind")]
    kind: Kind,
    #[serde(flatten)]
    keys: Value,
}
#[cfg(feature = "aead")]
impl From<crate::Aead> for Primitive {
    fn from(value: crate::Aead) -> Self {
        Primitive::Aead(value)
    }
}
#[cfg(feature = "aead")]
impl From<&crate::Aead> for Primitive {
    fn from(value: &crate::Aead) -> Self {
        Primitive::Aead(value.clone())
    }
}

#[cfg(feature = "daead")]
impl From<crate::Daead> for Primitive {
    fn from(value: crate::Daead) -> Self {
        Primitive::Daead(value)
    }
}

#[cfg(feature = "daead")]
impl From<&crate::Daead> for Primitive {
    fn from(value: &crate::Daead) -> Self {
        Primitive::Daead(value.clone())
    }
}

#[cfg(feature = "mac")]
impl From<crate::Mac> for Primitive {
    fn from(value: crate::Mac) -> Self {
        Primitive::Mac(value)
    }
}
#[cfg(feature = "mac")]
impl From<&crate::Mac> for Primitive {
    fn from(value: &crate::Mac) -> Self {
        Primitive::Mac(value.clone())
    }
}

#[cfg(feature = "dsa")]
impl From<crate::Signer> for Primitive {
    fn from(value: crate::Signer) -> Self {
        Primitive::Dsa(value)
    }
}
#[cfg(feature = "dsa")]
impl From<&crate::Signer> for Primitive {
    fn from(value: &crate::Signer) -> Self {
        Primitive::Dsa(value.clone())
    }
}

struct EncryptedKeyring<A>
where
    A: AsRef<[u8]>,
{
    key_and_nonce: Vec<u8>,
    ciphertext: Vec<u8>,
    aad: Aad<A>,
}
impl<A> core::fmt::Debug for EncryptedKeyring<A>
where
    A: AsRef<[u8]>,
{
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("EncryptedKeyring")
            .field("key_and_nonce", &self.key_and_nonce)
            .field("ciphertext", &self.ciphertext)
            .field("aad", &self.aad.as_ref())
            .finish()
    }
}
async fn seal_keyring_data<E, A>(
    envelope: &E,
    EncryptedKeyring {
        aad,
        key_and_nonce,
        ciphertext,
    }: EncryptedKeyring<A>,
) -> Result<Vec<u8>, SealError>
where
    E: 'static + Envelope,
    A: 'static + AsRef<[u8]> + Send + Sync,
{
    let dek = envelope
        .encrypt_dek(aad, key_and_nonce.clone())
        .await
        .map_err(|e| SealError(e.to_string()))?;
    check_seal(&key_and_nonce, &dek)?;
    Ok(encode_sealed_keyring(dek, ciphertext))
}

fn seal_keyring_data_sync<E, A>(
    envelope: &E,
    EncryptedKeyring {
        aad,
        key_and_nonce,
        ciphertext,
    }: EncryptedKeyring<A>,
) -> Result<Vec<u8>, SealError>
where
    E: crate::envelope::sync::Envelope,
    A: AsRef<[u8]>,
{
    let dek = envelope
        .encrypt_dek(aad, key_and_nonce.clone())
        .map_err(|e| SealError(e.to_string()))?;
    check_seal(&key_and_nonce, &dek)?;
    Ok(encode_sealed_keyring(dek, ciphertext))
}

fn encode_sealed_keyring(dek: Vec<u8>, sealed_keyring: Vec<u8>) -> Vec<u8> {
    let header = dek.len() as u32;
    let header = header.to_be_bytes();
    let result = [&header[..], &dek[..], &sealed_keyring[..]].concat();
    let len = result.len() as u64;
    let mut final_result = len.to_be_bytes().to_vec();
    final_result.extend(result);
    final_result
}

/// does a very rough check to ensure that if the data returned from the
/// [`Envelope`] is not the same as the data that was passed in. If so, the
/// [`Envelope`] failed to encrypt the key and nonce.
fn check_seal(key_and_nonce: &[u8], sealed_key_and_nonce: &[u8]) -> Result<(), SealError> {
    if sealed_key_and_nonce.len() >= key_and_nonce.len()
        && sealed_key_and_nonce[0..key_and_nonce.len()] == key_and_nonce[..]
    {
        Err(SealError("kms failed to seal".into()))
    } else {
        Ok(())
    }
}

fn encrypt_keyring_data<A>(aad: Aad<A>, mut data: Vec<u8>) -> Result<EncryptedKeyring<A>, SealError>
where
    A: AsRef<[u8]>,
{
    let key = Aes256Gcm::generate_key(&mut crate::SystemRng);
    let cipher = Aes256Gcm::new(&key);
    let nonce = Aes256Gcm::generate_nonce(&mut crate::SystemRng);
    data.reserve(AES_256_GCM_TAG_SIZE);
    cipher.encrypt_in_place(&nonce, aad.as_ref(), &mut data)?;
    let key_and_nonce = [key.as_slice(), nonce.as_slice()].concat().to_vec();

    // compresses the ciphertext using DEFALTE
    // let data = miniz_oxide::deflate::compress_to_vec(&data, 1);

    Ok(EncryptedKeyring {
        aad,
        key_and_nonce,
        ciphertext: data,
    })
}

fn read_encrypted(ciphertext: &[u8]) -> Result<Vec<u8>, OpenError> {
    if ciphertext.len() <= 8 {
        Err(OpenError("keyring data too short".to_string()))?
    }

    let len = u64::from_be_bytes(
        ciphertext[0..8]
            .try_into()
            .map_err(|_| OpenError("keyring data too short".to_string()))?,
    );

    if ciphertext.len() < len as usize + 8 {
        Err(OpenError("invalid keyring data".to_string()))?
    }
    if len > usize::MAX as u64 {
        Err(OpenError(
            "keyring data exceeds system len limits".to_string(),
        ))?
    }
    let len = len as usize;
    if ciphertext.len() < len + 8 {
        return Err("invalid keydata".into());
    }

    Ok(ciphertext[8..len + 8].to_vec())
}

fn open_keyring_data<A>(
    key: Vec<u8>,
    aad: Aad<A>,
    sealed: &[u8],
    sealed_cipher_and_nonce: &[u8],
) -> Result<Vec<u8>, OpenError>
where
    A: AsRef<[u8]>,
{
    let mut buffer = sealed[4 + sealed_cipher_and_nonce.len()..].to_vec();
    // let mut buffer = miniz_oxide::inflate::decompress_to_vec(&buffer)
    //     .map_err(|_| OpenError("keyring is incomplete or corrupt".to_string()))?;
    decrypt(key, aad.as_ref(), &mut buffer)?;
    Ok(buffer)
}

fn read_sealed_cipher_and_nonce(sealed: &[u8]) -> Result<Vec<u8>, OpenError> {
    let sealed_cipher_and_nonce_len = read_sealed_cipher_nonce_len(sealed)?;
    let sealed_cipher_and_nonce = &sealed[4..4 + sealed_cipher_and_nonce_len];
    Ok(sealed_cipher_and_nonce.to_vec())
}

fn decrypt(mut key_and_nonce: Vec<u8>, aad: &[u8], buffer: &mut Vec<u8>) -> Result<(), OpenError> {
    if key_and_nonce.len() != AES_256_GCM_KEY_SIZE + AES_256_GCM_NONCE_SIZE {
        return Err("invalid data returned from envelope".into());
    }
    let nonce = key_and_nonce.split_off(AES_256_GCM_KEY_SIZE);
    let key = key_and_nonce;
    let nonce = aes_gcm::Nonce::from_slice(&nonce);
    let cipher = Aes256Gcm::new_from_slice(&key)?;
    cipher.decrypt_in_place(nonce, aad, buffer)?;
    Ok(())
}

fn read_sealed_cipher_nonce_len(sealed: &[u8]) -> Result<usize, OpenError> {
    if sealed.len() < 4 {
        return Err("sealed data too short".into());
    }
    let sealed_cipher_and_nonce_len = u32::from_be_bytes(sealed[0..4].try_into().unwrap()); // safe: len checked above.
    if sealed_cipher_and_nonce_len < 4 {
        return Err("sealed data too short".into());
    }
    let sealed_cipher_and_nonce_len: usize = sealed_cipher_and_nonce_len
        .try_into()
        .map_err(|_| OpenError("sealed data too long".into()))?;

    if sealed.len() < 4 + sealed_cipher_and_nonce_len {
        return Err("sealed data too short".into());
    }

    Ok(sealed_cipher_and_nonce_len)
}

#[cfg(test)]
mod tests {
    use alloc::{boxed::Box, string::String, sync::Arc, vec};
    use futures::lock::Mutex;

    #[derive(Default)]
    struct MockEnvelope {
        expected_value: Arc<Mutex<Option<Vec<u8>>>>,
    }

    impl Envelope for MockEnvelope {
        type EncryptError = String;

        type DecryptError = String;

        fn encrypt_dek<A, P>(
            &self,
            _aad: Aad<A>,
            plaintext: P,
        ) -> core::pin::Pin<
            Box<dyn futures::Future<Output = Result<Vec<u8>, Self::EncryptError>> + Send + '_>,
        >
        where
            A: 'static + AsRef<[u8]> + Send + Sync,
            P: 'static + AsRef<[u8]> + Send + Sync,
        {
            Box::pin(async move {
                self.expected_value
                    .lock()
                    .await
                    .replace(plaintext.as_ref().to_vec());

                let v = vec![7u8; plaintext.as_ref().len() + 4];
                Ok(v)
            })
        }

        fn decrypt_dek<A, C>(
            &self,
            _aad: Aad<A>,
            ciphertext: C,
        ) -> core::pin::Pin<
            Box<dyn futures::Future<Output = Result<Vec<u8>, Self::DecryptError>> + Send + '_>,
        >
        where
            A: 'static + AsRef<[u8]> + Send + Sync,
            C: 'static + AsRef<[u8]> + Send + Sync,
        {
            Box::pin(async move {
                if !ciphertext.as_ref().iter().all(|&x| x == 7) {
                    return Err("invalid ciphertext".into());
                }
                Ok(self.expected_value.lock().await.take().unwrap())
            })
        }
    }

    use super::*;

    // #[cfg(feature = "mac")]
    // #[cfg(feature = "std")]
    // #[tokio::test]
    // async fn test_in_mock_seal_open_mac() {
    //     use crate::rand::MockRng;

    //     let mac = crate::mac::Mac::new(crate::mac::Algorithm::Sha256, None);
    //     let primary_key = mac.keyring.primary();

    //     let mock = MockEnvelope::default();
    //     // in a real application, you would use a real key management service.
    //     // InMemory is only suitable for testing.
    //     let data = crate::Mac::seal(&mac, Aad::empty(), &mock).await.unwrap();
    //     let mac = crate::Mac::open(Aad::empty(), data, &mock).await.unwrap();
    // }
}
