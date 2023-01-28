use crate::{gen_id, DecryptError, UnspecifiedError};
use byteorder::{BigEndian, ReadBytesExt};
use bytes::Buf;
use ring::{
    aead::{Aad, LessSafeKey, Nonce, UnboundKey},
    rand::{SecureRandom, SystemRandom},
};
use serde::{Deserialize, Serialize};
use serde_repr::{Deserialize_repr, Serialize_repr};
use std::fmt::Debug;
use std::io::{Cursor, Read};
pub struct Aead {
    keys: Vec<Key>,
    primary_key_id: u32,
}

impl Aead {
    pub fn new(algorithm: Algorithm) -> Result<Self, UnspecifiedError> {
        let key = Key::new(algorithm)?;
        let kid = key.id;
        Ok(Self {
            keys: vec![key],
            primary_key_id: kid,
        })
    }
}

#[derive(Serialize_repr, Deserialize_repr, PartialEq, Eq, Clone, Copy, Debug)]
#[repr(u8)]
pub enum Algorithm {
    ChaCha20Poly1305,
    Aes128Gcm,
    Aes256Gcm,
}

impl Algorithm {
    /// The length of the nonce in bytes
    pub fn nonce_len(&self) -> usize {
        self.ring().nonce_len()
    }
    /// The length of the nonce prefix in bytes defined by
    /// the nonce length minus 4 bytes (u32) for the sequence number
    /// and 1 byte to indicate the final block
    pub fn nonce_prefix_len(&self) -> usize {
        self.ring().nonce_len() - 4 - 1
    }

    /// The length of the tag in bytes
    pub fn tag_len(&self) -> usize {
        self.ring().key_len()
    }
    /// The length of the key in bytes
    pub fn key_len(&self) -> usize {
        self.ring().key_len()
    }

    fn ring(&self) -> &'static ring::aead::Algorithm {
        match self {
            Algorithm::ChaCha20Poly1305 => &ring::aead::CHACHA20_POLY1305,
            Algorithm::Aes128Gcm => &ring::aead::AES_128_GCM,
            Algorithm::Aes256Gcm => &ring::aead::AES_256_GCM,
        }
    }

    fn load_key(&self, key: &[u8]) -> Result<LessSafeKey, ring::error::Unspecified> {
        UnboundKey::new(self.ring(), key).map(LessSafeKey::new)
    }
}

#[derive(Serialize, Deserialize)]
#[serde(try_from = "KeyData")]
#[serde(into = "KeyData")]
struct Key {
    id: u32,
    algorithm: Algorithm,
    key: LessSafeKey,
    data: Vec<u8>,
}
impl Clone for Key {
    fn clone(&self) -> Self {
        Self {
            id: self.id,
            algorithm: self.algorithm,
            key: self.algorithm.load_key(&self.data).unwrap(),
            data: self.data.clone(),
        }
    }
}
impl Key {
    fn new(algorithm: Algorithm) -> Result<Self, UnspecifiedError> {
        let rng = SystemRandom::new();
        let mut data = vec![0; algorithm.key_len()];
        rng.fill(&mut data)?;
        let key = algorithm.load_key(&data)?;
        let id = gen_id();
        Ok(Self {
            id,
            algorithm,
            key,
            data,
        })
    }

    pub fn id(&self) -> u32 {
        self.id
    }

    pub fn encrypt(
        &self,
        cleartext: &[u8],
        additional_data: &[u8],
    ) -> Result<Vec<u8>, UnspecifiedError> {
        let mut buf = cleartext.to_owned();
        let mut nonce_value = vec![0; self.algorithm.nonce_len()];
        SystemRandom::new().fill(&mut nonce_value)?;
        let nonce = Nonce::try_assume_unique_for_key(&nonce_value)?;
        let aad = Aad::from(additional_data);
        self.key.seal_in_place_append_tag(nonce, aad, &mut buf)?;
        let header = [&[Method::Block.into()], &self.id_bytes()[..], &nonce_value].concat();
        Ok(buf.splice(0..0, header).collect())
    }

    pub fn decrypt(
        &self,
        ciphertext: &[u8],
        additional_data: &[u8],
    ) -> Result<Vec<u8>, DecryptError> {
        let mut cursor = Cursor::new(ciphertext);
        let method = cursor.read_u8().unwrap(); // safe, checked above
        let method = Method::try_from(method).map_err(DecryptError::Malformed)?;
        todo!()
    }
    fn read_method_and_id(
        &self,
        cursor: &mut Cursor<&[u8]>,
    ) -> Result<(Method, u32), DecryptError> {
        let method = Method::try_from(cursor.get_u8()).map_err(DecryptError::Malformed)?;
        let id = cursor.read_u32::<BigEndian>().unwrap(); // safe, checked before called

        Ok((method, id))
    }
    fn id_bytes(&self) -> [u8; 4] {
        self.id.to_be_bytes()
    }
    // The length of the key id in bytes
    fn id_len() -> usize {
        4
    }
}
impl TryFrom<KeyData> for Key {
    type Error = ring::error::Unspecified;
    fn try_from(value: KeyData) -> Result<Self, Self::Error> {
        let key = value.algorithm.load_key(&value.data)?;
        Ok(Self {
            id: value.id,
            algorithm: value.algorithm,
            key,
            data: value.data,
        })
    }
}
impl Debug for Key {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Key")
            .field("id", &self.id)
            .field("algorithm", &self.algorithm)
            .field("value", &"***")
            .finish()
    }
}

#[derive(Serialize, Deserialize)]
struct KeyData {
    id: u32,
    algorithm: Algorithm,
    #[serde(with = "hex")]
    data: Vec<u8>,
}
impl From<Key> for KeyData {
    fn from(value: Key) -> Self {
        Self {
            id: value.id,
            algorithm: value.algorithm,
            data: value.data,
        }
    }
}

enum Header {
    Block {
        method: Method,
        kid: u32,
        nonce: Nonce,
    },
    Stream {
        method: Method,
        kid: u32,
        seed: Vec<u8>,
        block_size: u16,
    },
}
impl Header {
    fn parse(algorithm: Algorithm, cursor: &mut Cursor<&[u8]>) -> Result<Self, DecryptError> {
        let method = cursor
            .read_u8()
            .map_err(|_| DecryptError::Malformed("invalid ciphertext".into()))?;
        let method = Method::try_from(method).map_err(DecryptError::Malformed)?;

        if cursor.remaining() < method.remaining_header_len(algorithm) {
            return Err(DecryptError::Malformed("invalid ciphertext".into()));
        }

        let kid = cursor.read_u32::<BigEndian>().unwrap(); // safe, len is checked above.
        match method {
            Method::Block => {
                let mut nonce = vec![0; algorithm.nonce_len()];
                cursor.read_exact(&mut nonce).unwrap();
                let nonce = Nonce::try_assume_unique_for_key(&nonce)?;
                Ok(Header::Block { method, kid, nonce })
            }
            Method::Stream => {
                let block_size = cursor.read_u16::<BigEndian>().unwrap(); // safe, len is checked above.
                let mut seed = vec![0; algorithm.nonce_prefix_len()];
                cursor.read_exact(&mut seed).unwrap(); // safe, len checked above.

                Ok(Header::Stream {
                    method,
                    kid,
                    seed,
                    block_size,
                })
            }
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
/// First byte of the encrypted data which indicates the method of encryption.
enum Method {
    /// full block with constant memory while making a single left-to-right pass
    ///
    /// ie, `key.encrypt(plaintext, aad)`
    Block,
    /// streamed with a constant block size using the STREAM method as described by
    /// [Online Authenticated-Encryption and its Nonce-Reuse Misuse-Resistance](https://eprint.iacr.org/2015/189.pdf)
    Stream,
}
impl Method {
    fn header_len(&self, algorithm: Algorithm) -> usize {
        match self {
            Method::Block => Method::len() + Key::id_len() + algorithm.nonce_len(),
            // method + key id + block size in kilobytes + nonce prefix
            Method::Stream => Method::len() + Key::id_len() + algorithm.nonce_prefix_len() + 2,
        }
    }
    fn remaining_header_len(&self, algorithm: Algorithm) -> usize {
        self.header_len(algorithm) - Method::len()
    }
    fn len() -> usize {
        1
    }
}
impl From<Method> for u8 {
    fn from(method: Method) -> Self {
        method as u8
    }
}
impl TryFrom<u8> for Method {
    type Error = String;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Method::Block),
            1 => Ok(Method::Stream),
            _ => Err("missing or unknown encryption method".to_string()),
        }
    }
}
