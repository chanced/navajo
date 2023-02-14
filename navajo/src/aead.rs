mod algorithm;
mod cipher;
mod ciphertext_info;
mod decryptor;
mod encryptor;
mod header;
mod key_info;
mod material;
mod method;
mod nonce;
mod segment;
mod size;
mod writer;
use nonce::Nonce;

use alloc::vec::Vec;
pub use key_info::AeadKeyInfo;

use crate::{
    error::{KeyNotFoundError, RemoveKeyError},
    key::Key,
    keyring::Keyring,
    Buffer,
};
pub use algorithm::Algorithm;
pub use ciphertext_info::CiphertextInfo;
pub use encryptor::StreamEncryptor;
pub use method::Method;
pub use segment::Segment;
use size::Size;
// use cipher::{ciphers, ring_ciphers, Cipher};

use material::Material;

pub struct Aead {
    keyring: Keyring<Material>,
}
impl Aead {
    pub fn new(algorithm: Algorithm, meta: Option<serde_json::Value>) -> Aead {
        Self {
            keyring: Keyring::new(Material::new(algorithm), crate::Origin::Generated, meta),
        }
    }
    pub fn add_key(&mut self, algorithm: Algorithm, meta: Option<serde_json::Value>) -> &mut Self {
        self.keyring
            .add(Material::new(algorithm), crate::Origin::Generated, meta);
        self
    }
    /// Returns [`AeadKeyInfo`] for the primary key.
    pub fn primary_key(&self) -> AeadKeyInfo {
        self.keyring.primary_key().into()
    }
    /// Returns a [`Vec`] containing [`AeadKeyInfo`] for each key in this keyring.
    pub fn keys(&self) -> Vec<AeadKeyInfo> {
        self.keyring.keys().iter().map(AeadKeyInfo::new).collect()
    }

    pub fn encrypt_in_place<B: Buffer>(
        &self,
        data: &mut B,
        aad: &[u8],
    ) -> Result<(), crate::error::EncryptError> {
        self.keyring.primary_key().encrypt_in_place(data, aad)
    }

    pub fn promote_key(
        &mut self,
        key_id: impl Into<u32>,
    ) -> Result<AeadKeyInfo, crate::error::KeyNotFoundError> {
        self.keyring.promote(key_id).map(AeadKeyInfo::new)
    }

    pub fn disable_key(
        &mut self,
        key_id: impl Into<u32>,
    ) -> Result<AeadKeyInfo, crate::error::DisableKeyError<Algorithm>> {
        self.keyring.disable(key_id).map(AeadKeyInfo::new)
    }

    pub fn enable_key(&mut self, key_id: impl Into<u32>) -> Result<AeadKeyInfo, KeyNotFoundError> {
        self.keyring.enable(key_id).map(AeadKeyInfo::new)
    }

    pub fn remove_key(
        &mut self,
        key_id: impl Into<u32>,
    ) -> Result<AeadKeyInfo, RemoveKeyError<Algorithm>> {
        self.keyring.remove(key_id).map(|k| AeadKeyInfo::new(&k))
    }

    pub fn update_key_meta(
        &mut self,
        key_id: impl Into<u32>,
        meta: Option<serde_json::Value>,
    ) -> Result<AeadKeyInfo, KeyNotFoundError> {
        self.keyring.update_meta(key_id, meta).map(AeadKeyInfo::new)
    }
}
// mod algorithm;
// mod ciphertext_info;
// mod header;
// mod method;
// mod nonce;
// mod segment;
// mod stream;

// pub use algorithm::Algorithm;
// pub use ciphertext_info::CiphertextInfo;
// pub use method::Method;
// use nonce::Nonce;
// pub use segment::Segment;
// pub use stream::{Decrypt, DecryptStream, Encrypt, EncryptStream};

// use crate::error::{
//     DecryptError, EncryptError, KeyNotFoundError, MalformedError, UnspecifiedError,
// };
// use crate::{gen_id, id::gen_unique_id, rand, timestamp, KeyInfo, KeyStatus};
// use core::fmt;

// use ring::{
//     aead::{Aad, LessSafeKey},
//     hkdf::{self},
// };

// use serde::{Deserialize, Serialize};
// use std::{collections::HashSet, io::Cursor, mem, sync::Arc};

// use self::header::Header;
// use crate::salt::Salt;

// #[derive(Debug, Clone, Serialize, Deserialize)]
// pub struct Aead {
//     keys: Vec<Arc<Key>>, // <-- todo, make this Arc<Vec<Arc<Key>>>
//     primary_key_id: u32,
//     primary_key: Arc<Key>,
// }

// impl Aead {
//     /// Creates a new AEAD keyring with a single key of the specified [`Algorithm`].
//     ///
//     ///
//     /// ## Errors
//     /// If the underlying crypto library returns an error during key generation,
//     /// this function will return an UnspecifiedError.
//     pub fn new(algorithm: Algorithm) -> Result<Self, UnspecifiedError> {
//         let key = Arc::new(Key::new(gen_id()?, algorithm)?);
//         let kid = key.id;
//         Ok(Self {
//             keys: vec![key.clone()],
//             primary_key_id: kid,
//             primary_key: key,
//         })
//     }

//     pub fn keys(&self) -> Vec<KeyInfo<Algorithm>> {
//         self.keys
//             .iter()
//             .map(|k| self.key_info(k.id).unwrap())
//             .collect()
//     }

//     pub fn key_info(&self, kid: u32) -> Option<KeyInfo<Algorithm>> {
//         self.key(kid).map(|k| KeyInfo {
//             id: k.id,
//             algorithm: k.algorithm,
//             status: self.key_status(kid).unwrap(),
//             created_at_timestamp: k.timestamp,
//             pub_key: None,
//         })
//     }

//     fn key_status(&self, kid: u32) -> Option<KeyStatus> {
//         if kid == self.primary_key_id {
//             Some(KeyStatus::Primary)
//         } else {
//             Some(KeyStatus::Secondary)
//         }
//     }
//     /// dds a new AEAD key for provided [`Algorithm`]. [`KeyInfo`] is returned
//     /// if the generation process is successful.
//     pub fn add_key(
//         &mut self,
//         algorithm: Algorithm,
//     ) -> Result<KeyInfo<Algorithm>, UnspecifiedError> {
//         let id = gen_unique_id(&self.key_ids())?;
//         let key = Arc::new(Key::new(id, algorithm)?);
//         self.keys.push(key);
//         self.key_info(id).ok_or(UnspecifiedError)
//     }

//     fn key_ids(&self) -> HashSet<u32> {
//         self.keys.iter().map(|k| k.id).collect()
//     }
//     pub fn set_primary_key(&mut self, kid: u32) -> Result<(), KeyNotFoundError> {
//         if self.key(kid).is_none() {
//             return Err(KeyNotFoundError(kid));
//         }
//         self.primary_key_id = kid;
//         Ok(())
//     }

//     pub fn encrypt<A>(
//         &self,
//         cleartext: Vec<u8>,
//         additional_data: A,
//     ) -> Result<Vec<u8>, EncryptError>
//     where
//         A: AsRef<[u8]>,
//     {
//         let res = self.primary()?.encrypt(cleartext, additional_data)?;
//         Ok(res)
//     }

//     pub fn primary_key(&self) -> Result<KeyInfo<Algorithm>, KeyNotFoundError> {
//         self.key_info(self.primary_key_id)
//             .ok_or(KeyNotFoundError(self.primary_key_id))
//     }

//     fn primary(&self) -> Result<Arc<Key>, EncryptError> {
//         self.keys
//             .iter()
//             .find(|k| k.id == self.primary_key_id)
//             .ok_or(EncryptError::MissingPrimaryKey)
//             .cloned()
//     }
//     fn key(&self, id: u32) -> Result<Arc<Key>, KeyNotFoundError> {
//         self.keys
//             .iter()
//             .find(|k| k.id == id)
//             .cloned()
//             .ok_or(KeyNotFoundError(id))
//     }
// }

// #[derive(Serialize, Deserialize)]
// #[serde(try_from = "KeyData")]
// #[serde(into = "KeyData")]
// struct Key {
//     id: u32,
//     algorithm: Algorithm,
//     key: LessSafeKey,
//     timestamp: u64,
//     bytes: Vec<u8>,
//     #[serde(skip)]
//     salt: Option<Salt>,
// }

// impl Clone for Key {
//     fn clone(&self) -> Self {
//         Self {
//             id: self.id,
//             algorithm: self.algorithm,
//             key: self.algorithm.load_key(&self.bytes).unwrap(), // safe or this key wouldn't exist
//             bytes: self.bytes.clone(),
//             timestamp: self.timestamp,
//             salt: self.salt.clone(),
//         }
//     }
// }
// impl Key {
//     fn new(id: u32, algorithm: Algorithm) -> Result<Self, UnspecifiedError> {
//         let mut data = vec![0; algorithm.key_len()];
//         rand::fill(&mut data)?;
//         let key = algorithm.load_key(&data)?;

//         Ok(Self {
//             id,
//             algorithm,
//             key,
//             bytes: data,
//             timestamp: timestamp::now(),
//             salt: None,
//         })
//     }

//     fn encrypt<C, A>(&self, cleartext: C, additional_data: A) -> Result<Vec<u8>, UnspecifiedError>
//     where
//         C: Into<Vec<u8>>,
//         A: AsRef<[u8]>,
//     {
//         let nonce = Nonce::new(self.algorithm, false)?;
//         let header = Header {
//             key_id: self.id,
//             method: Method::Online,
//             nonce: nonce.into(),
//             salt: None,
//         };
//         let mut cleartext = cleartext.into();
//         let mut buf = Vec::with_capacity(header.len() + cleartext.len());
//         let aad = Aad::from(additional_data);
//         let nonce = &header.nonce;
//         self.key
//             .seal_in_place_append_tag(nonce.try_into()?, aad, &mut cleartext)?;
//         header.write(&mut buf);
//         buf.append(&mut cleartext);
//         Ok(buf)
//     }

//     fn encrypt_segment<T, A>(
//         &self,
//         cleartext: &mut T,
//         additional_data: A,
//         nonce: &Nonce,
//     ) -> Result<(), UnspecifiedError>
//     where
//         T: AsMut<[u8]> + for<'in_out> Extend<&'in_out u8>,
//         A: AsRef<[u8]>,
//     {
//         let aad = Aad::from(additional_data);
//         self.key
//             .seal_in_place_append_tag(nonce.try_into()?, aad, cleartext)?;
//         Ok(())
//     }

//     fn decrypt(&self, mut buf: Vec<u8>, additional_data: &[u8]) -> Result<Vec<u8>, DecryptError> {
//         if buf.len() < self.algorithm.nonce_len() {
//             return Err(DecryptError::Malformed("cipher text too short".into()));
//         }
//         let mut nonce = buf.split_off(self.algorithm.nonce_len());
//         mem::swap(&mut buf, &mut nonce);
//         let nonce = ring::aead::Nonce::try_assume_unique_for_key(&nonce)?;
//         let aad = Aad::from(additional_data);
//         let len = { self.key.open_in_place(nonce, aad, &mut buf)?.len() };
//         _ = buf.split_off(len);
//         Ok(buf)
//     }

//     fn derive_key(&self, aad: &[u8]) -> Result<Arc<Key>, UnspecifiedError> {
//         let salt = match &self.salt {
//             Some(salt) => salt.clone(),
//             None => {
//                 let mut salt = vec![0; self.algorithm.key_len()];
//                 rand::fill(&mut salt)?;
//                 salt::Salt::new(hkdf::HKDF_SHA256, salt)
//             }
//         };
//         let v = vec![0; self.algorithm.key_len()];
//         let mut buf = vec![0; self.algorithm.key_len()];
//         salt.extract(&self.bytes)
//             .expand(&[aad], salt.algorithm())?
//             .fill(&mut buf)?;
//         Ok(Arc::new(Key {
//             id: self.id,
//             algorithm: self.algorithm,
//             key: self.algorithm.load_key(&buf)?,
//             bytes: buf,
//             salt: Some(salt),
//             timestamp: timestamp::now(),
//         }))
//     }
//     fn derive_key_from_salt(&self, salt: &[u8], aad: &[u8]) -> Result<Arc<Key>, UnspecifiedError> {
//         let salt = salt::Salt::new(hkdf::HKDF_SHA256, salt.to_vec());
//         let mut buf = vec![0; self.algorithm.key_len()];
//         salt.extract(&self.bytes)
//             .expand(&[aad], salt.algorithm())?
//             .fill(&mut buf)?;
//         Ok(Arc::new(Key {
//             id: self.id,
//             algorithm: self.algorithm,
//             key: self.algorithm.load_key(&buf)?,
//             bytes: buf,
//             salt: Some(salt),
//             timestamp: timestamp::now(),
//         }))
//     }
// }

// impl TryFrom<KeyData> for Key {
//     type Error = ring::error::Unspecified;
//     fn try_from(value: KeyData) -> Result<Self, Self::Error> {
//         let key = value.algorithm.load_key(&value.data)?;
//         Ok(Self {
//             id: value.id,
//             algorithm: value.algorithm,
//             key,
//             bytes: value.data,
//             timestamp: value.timestamp,
//             salt: None,
//         })
//     }
// }
// impl fmt::Debug for Key {
//     fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
//         f.debug_struct("Key")
//             .field("id", &self.id)
//             .field("algorithm", &self.algorithm)
//             .field("value", &"***")
//             .finish()
//     }
// }

// #[derive(Serialize, Deserialize)]
// struct KeyData {
//     id: u32,
//     algorithm: Algorithm,
//     timestamp: u64,
//     #[serde(with = "hex")]
//     data: Vec<u8>,
// }
// impl From<Key> for KeyData {
//     fn from(value: Key) -> Self {
//         Self {
//             id: value.id,
//             algorithm: value.algorithm,
//             data: value.bytes,
//             timestamp: value.timestamp,
//         }
//     }
// }

// fn parse_header(&self, ciphertext: &[u8]) -> Result<Header, DecryptError> {
// 	if ciphertext.len() < 5 {
// 		return Err(DecryptError::Malformed("ciphertext too short".into()));
// 	}
// 	let method = Method::try_from(ciphertext[0])?;

// 	let kid = u32::from_be_bytes(ciphertext[1..6].try_into().unwrap()); // safe; checked above
// 	let key = self.key(kid)?;
// 	match method {
// 		Method::Online => todo!(),
// 		Method::StreamHmacSha256(_) => todo!(),
// 	}
// 	Ok((method, kid))
// }

// pub fn decrypt<C, A>(&self, ciphertext: C, additional_data: A) -> Result<Vec<u8>, DecryptError>
// where
// 	C: AsRef<[u8]>,
// 	A: AsRef<[u8]>,
// {
// 	let mut buf = Vec::from(ciphertext.as_ref());
// 	if buf.len() < 5 {
// 		return Err(DecryptError::Malformed("ciphertext too short".into()));
// 	}
// 	let method = Method::try_from(0)?;
// 	let key_id = mem::replace(&mut buf, tmp);
// 	let kid = u32::from_be_bytes(key_id[..].try_into().unwrap()); // safe, len checked above.
// 	let key = self.key(kid).ok_or(DecryptError::KeyNotFound(kid))?;

// 	match method {
// 		Method::Online => key.decrypt(buf, additional_data.as_ref()),
// 		Method::StreamHmacSha256(seg) => todo!(),
// 	}
// }

#[cfg(test)]
mod tests {

    // // use crate::rand::*;
    // #[test]
    // fn test_encrypt_produces_correct_header() -> Result<(), Box<dyn std::error::Error>> {
    //     let ks = Aead::new(Algorithm::Aes256Gcm)?;
    //     let k = ks.primary_key()?;
    //     let cleartext = b"hello world";
    //     let additional_data = b"additional data";
    //     let res = ks.encrypt(cleartext[..].into(), additional_data)?;
    //     let mut buf = Vec::with_capacity(res.len());
    //     buf.extend_from_slice(&res);

    //     assert_eq!(
    //         buf.len(),
    //         1 + 4 + k.algorithm.nonce_len() + cleartext.len() + k.algorithm.tag_len()
    //     );
    //     let mut cursor = Cursor::new(buf);
    //     assert_eq!(cursor.read_u8().unwrap(), Method::Online);
    //     assert_eq!(
    //         cursor.read_u32::<BigEndian>().unwrap(),
    //         ks.primary_key().unwrap().id
    //     );
    //     assert_eq!(
    //         cursor.get_ref().len() - cursor.position() as usize,
    //         k.algorithm.nonce_len() + cleartext.len() + k.algorithm.tag_len()
    //     );
    //     Ok(())
    // }
    // #[test]
    // fn test_encrypt_selects_primary_key() -> Result<(), Box<dyn std::error::Error>> {
    //     let ks = Aead::new(Algorithm::Aes256Gcm)?;
    //     let k = ks.primary_key()?;
    //     let cleartext = b"hello world";
    //     let additional_data = b"additional data";
    //     let res = ks.encrypt(cleartext[..].into(), additional_data)?;
    //     let mut buf = Vec::with_capacity(res.len());
    //     buf.extend_from_slice(&res);
    //     let mut cursor = Cursor::new(buf);
    //     assert_eq!(cursor.read_u8().unwrap(), Method::Online);
    //     assert_eq!(
    //         cursor.read_u32::<BigEndian>().unwrap(),
    //         ks.primary_key().unwrap().id
    //     );
    //     assert_eq!(
    //         cursor.get_ref().len() - cursor.position() as usize,
    //         k.algorithm.nonce_len() + cleartext.len() + k.algorithm.tag_len()
    //     );
    //     Ok(())
    // }
    // #[test]
    // fn test_round_trip() -> Result<(), Box<dyn std::error::Error>> {
    //     let ks = Aead::new(Algorithm::Aes256Gcm)?;
    //     let k = ks.primary_key()?;
    //     println!("{:?}", k);
    //     let cleartext = b"hello world!";
    //     let additional_data = b"additional data";
    //     let res = ks.encrypt(cleartext[..].into(), additional_data)?;
    //     let mut buf = Vec::with_capacity(res.len());
    //     buf.extend_from_slice(&res);
    //     let ciphertext = buf.clone();
    //     assert_eq!(
    //         buf.len(),
    //         1 + 4 + k.algorithm.nonce_len() + cleartext.len() + k.algorithm.tag_len()
    //     );
    //     let mut buf_data = buf.clone();
    //     let mut cursor = Cursor::new(buf);
    //     assert_eq!(cursor.read_u8().unwrap(), Method::Online);
    //     assert_eq!(
    //         cursor.read_u32::<BigEndian>().unwrap(),
    //         ks.primary_key().unwrap().id
    //     );
    //     assert_eq!(
    //         cursor.get_ref().len() - cursor.position() as usize,
    //         k.algorithm.nonce_len() + cleartext.len() + k.algorithm.tag_len()
    //     );
    //     cursor.set_position(cursor.position() + k.algorithm.nonce_len() as u64);
    //     let mut encrypted = buf_data.split_off(cleartext.len());

    //     println!("cleartext:{}", &String::from_utf8_lossy(&cleartext[..]));
    //     println!("encrypted:{}", &String::from_utf8_lossy(&encrypted));
    //     assert_ne!(encrypted, cleartext[..]);
    //     let decrypted = ks.decrypt(ciphertext, additional_data).unwrap();
    //     println!("{}", &String::from_utf8_lossy(&decrypted));
    //     assert_eq!(&decrypted, &cleartext[..]);
    //     Ok(())
    // }
}
