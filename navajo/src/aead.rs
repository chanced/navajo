use crate::{
    gen_id, key_id_len, rand::DefaultRandom, timestamp, DecryptError, EncryptError,
    InvalidBlockSizeError, KeyInfo, KeyNotFoundError, KeyStatus, UnspecifiedError,
};
use bytes::{Buf, BufMut, Bytes, BytesMut};
use core::fmt;
use ring::{
    aead::{Aad, LessSafeKey, Nonce, UnboundKey},
    rand::{SecureRandom, SystemRandom},
};
use serde::{Deserialize, Serialize};
use serde_repr::{Deserialize_repr as DeserializeRepr, Serialize_repr as SerializeRepr};
use std::{default, marker::PhantomData};

const FOUR_KB: u32 = 4096;
const SIXTY_FOUR_KB: u32 = 65536;
const ONE_MB: u32 = 1048576;
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Aead<R = crate::rand::DefaultRandom> {
    keys: Vec<Key>,
    primary_key_id: u32,
    rand: PhantomData<R>,
}

impl<R> Aead<R>
where
    R: crate::rand::Rand,
{
    /// Creates a new AEAD keyring with a single key of the specified [`Algorithm`].
    ///
    ///
    /// ## Errors
    /// If the underlying crypto library returns an error during key generation,
    /// this function will return an UnspecifiedError.
    pub fn new(algorithm: Algorithm) -> Result<Self, UnspecifiedError> {
        let key = Key::new(algorithm)?;
        let kid = key.id;
        Ok(Self {
            keys: vec![key],
            primary_key_id: kid,
            rand: PhantomData,
        })
    }

    pub fn keys(&self) -> Vec<KeyInfo<Algorithm>> {
        self.keys
            .iter()
            .map(|k| self.key_info(k.id).unwrap())
            .collect()
    }

    pub fn key_info(&self, kid: u32) -> Option<KeyInfo<Algorithm>> {
        self.key_by_id(kid).map(|k| KeyInfo {
            id: k.id,
            algorithm: k.algorithm,
            status: self.key_status(kid).unwrap(),
            created_at_timestamp: k.timestamp,
            pub_key: None,
        })
    }
    pub fn key_status(&self, kid: u32) -> Option<KeyStatus> {
        if kid == self.primary_key_id {
            Some(KeyStatus::Primary)
        } else {
            Some(KeyStatus::Secondary)
        }
    }
    /// adds a new AEAD key to the Aead instance. The key id is returned if the
    /// generation process is successful.
    pub fn add_key(&mut self, algorithm: Algorithm) -> Result<u32, UnspecifiedError> {
        let key = Key::new(algorithm)?;
        let kid = key.id;
        self.keys.push(key);
        Ok(kid)
    }
    pub fn set_primary_key(&mut self, kid: u32) -> Result<(), KeyNotFoundError> {
        if self.key_by_id(kid).is_none() {
            return Err(KeyNotFoundError(kid));
        }
        self.primary_key_id = kid;
        Ok(())
    }

    pub fn encrypt<A>(&self, cleartext: Bytes, additional_data: A) -> Result<Bytes, EncryptError>
    where
        A: AsRef<[u8]>,
    {
        let key = self
            .keys
            .iter()
            .find(|k| k.id == self.primary_key_id)
            .ok_or(EncryptError::MissingPrimaryKey)?;
        let res = key.encrypt(cleartext, additional_data)?;
        Ok(res)
    }

    pub fn decrypt<C, A>(&self, ciphertext: C, additional_data: A) -> Result<Bytes, DecryptError>
    where
        C: AsRef<[u8]>,
        A: AsRef<[u8]>,
    {
        let mut buf = BytesMut::from(ciphertext.as_ref());
        if buf.remaining() < 5 {
            return Err(DecryptError::Malformed("ciphertext too short".into()));
        }
        let method = Method::parse(&mut buf)?;
        let kid = buf.get_u32();
        let key = self.key_by_id(kid).ok_or(DecryptError::UnknownKey(kid))?;
        match method {
            Method::Block => key.decrypt(buf, additional_data.as_ref()),
            Method::Stream => todo!(),
        }
    }

    pub fn primary_key_id(&self) -> u32 {
        self.primary_key_id
    }
    fn primary_key(&self) -> Result<&Key, EncryptError> {
        self.keys
            .iter()
            .find(|k| k.id == self.primary_key_id)
            .ok_or(EncryptError::MissingPrimaryKey)
    }
    fn key_by_id(&self, id: u32) -> Option<&Key> {
        self.keys.iter().find(|k| k.id == id)
    }
}

/// Defines the size of the block segments used during STREAM encryption /
/// decription.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum SegmentSize {
    FourKB,
    SixtyFourKB,
    OneMB,
    Of(u32),
}

impl SegmentSize {
    #[allow(clippy::wrong_self_convention)]
    fn len() -> usize {
        4
    }
}
impl SegmentSize {
    fn validate(&self) -> Result<(), InvalidBlockSizeError> {
        match self {
            Self::FourKB => Ok(()),
            Self::SixtyFourKB => Ok(()),
            Self::OneMB => Ok(()),
            Self::Of(n) => {
                if *n < 1024 {
                    Err(InvalidBlockSizeError(*n))
                } else {
                    Ok(())
                }
            }
        }
    }
    fn to_be_bytes(&self) -> [u8; 4] {
        self.as_u32().to_be_bytes()
    }

    fn as_u32(&self) -> u32 {
        match self {
            Self::FourKB => FOUR_KB,
            Self::SixtyFourKB => SIXTY_FOUR_KB,
            Self::OneMB => ONE_MB,
            Self::Of(n) => *n,
        }
    }
}
impl From<u32> for SegmentSize {
    fn from(value: u32) -> Self {
        match value {
            FOUR_KB => Self::FourKB,
            SIXTY_FOUR_KB => Self::SixtyFourKB,
            ONE_MB => Self::OneMB,
            _ => Self::Of(value),
        }
    }
}

impl From<SegmentSize> for [u8; 4] {
    fn from(value: SegmentSize) -> Self {
        value.as_u32().to_be_bytes()
    }
}

impl From<SegmentSize> for u32 {
    fn from(bs: SegmentSize) -> Self {
        match bs {
            SegmentSize::FourKB => FOUR_KB,
            SegmentSize::SixtyFourKB => SIXTY_FOUR_KB,
            SegmentSize::OneMB => ONE_MB,
            SegmentSize::Of(v) => v,
        }
    }
}

#[derive(SerializeRepr, DeserializeRepr, PartialEq, Eq, Clone, Copy, Debug)]
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
        self.ring().tag_len()
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

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CiphertextInfo {
    pub key_id: u32,
    pub algorithm: Algorithm,
    pub method: Method,
    pub block_size: Option<u32>,
}

#[derive(Serialize, Deserialize)]
#[serde(try_from = "KeyData")]
#[serde(into = "KeyData")]
struct Key<R = DefaultRandom>
where
    R: Clone,
{
    id: u32,
    algorithm: Algorithm,
    key: LessSafeKey,
    timestamp: u64,
    data: Vec<u8>,
    #[serde(skip)]
    _rand: PhantomData<R>,
}
impl<R> Clone for Key<R>
where
    R: Clone,
{
    fn clone(&self) -> Self {
        Self {
            id: self.id,
            algorithm: self.algorithm,
            key: self.algorithm.load_key(&self.data).unwrap(),
            data: self.data.clone(),
            timestamp: self.timestamp,
            _rand: PhantomData,
        }
    }
}
impl<R> Key<R>
where
    R: crate::rand::Rand,
{
    fn new(algorithm: Algorithm) -> Result<Self, UnspecifiedError> {
        let rng = R::new();
        let mut data = vec![0; algorithm.key_len()];
        rng.fill(&mut data)?;
        let key = algorithm.load_key(&data)?;
        let id = gen_id();
        Ok(Self {
            id,
            algorithm,
            key,
            data,
            timestamp: timestamp::now(),
            _rand: PhantomData,
        })
    }

    fn id(&self) -> u32 {
        self.id
    }
    fn encrypt<A>(&self, cleartext: Bytes, additional_data: A) -> Result<Bytes, UnspecifiedError>
    where
        A: AsRef<[u8]>,
    {
        let cleartext = cleartext.as_ref();
        let nonce = self.gen_nonce()?;
        let mut buf = BytesMut::with_capacity(
            cleartext.len()
                + self.algorithm.tag_len()
                + Method::header_len(&Method::Block, self.algorithm),
        );
        buf.put_u8(Method::Block.into());
        buf.put_u32(self.id);
        buf.put_slice(nonce.as_ref());
        let header_len = buf.len();
        buf.put_slice(cleartext);
        let mut in_out = buf.split_off(header_len);
        let aad = Aad::from(additional_data);
        self.key.seal_in_place_append_tag(nonce, aad, &mut in_out)?;
        buf.unsplit(in_out);
        Ok(buf.freeze())
    }

    pub fn decrypt(
        &self,
        mut buf: BytesMut,
        additional_data: &[u8],
    ) -> Result<Bytes, DecryptError> {
        if buf.remaining() < self.algorithm.nonce_len() {
            return Err(DecryptError::Malformed("cipher text too short".into()));
        }
        let nonce = Nonce::try_assume_unique_for_key(&buf.split_to(self.algorithm.nonce_len()))?;
        let aad = Aad::from(additional_data);
        let len = { self.key.open_in_place(nonce, aad, &mut buf)?.len() };
        buf.truncate(len);
        Ok(buf.freeze())
    }

    fn gen_nonce(&self) -> Result<Nonce, UnspecifiedError> {
        let mut nonce_value = vec![0; self.algorithm.nonce_len()];
        SystemRandom::new().fill(&mut nonce_value)?;
        let nonce = Nonce::try_assume_unique_for_key(&nonce_value)?;
        Ok(nonce)
    }
    // The length of the key id in bytes
}

impl<R> TryFrom<KeyData> for Key<R>
where
    R: Clone,
{
    type Error = ring::error::Unspecified;
    fn try_from(value: KeyData) -> Result<Self, Self::Error> {
        let key = value.algorithm.load_key(&value.data)?;
        Ok(Self {
            id: value.id,
            algorithm: value.algorithm,
            key,
            data: value.data,
            timestamp: value.timestamp,
            _rand: default::Default::default(),
        })
    }
}
impl fmt::Debug for Key {
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
    timestamp: u64,
    #[serde(with = "hex")]
    data: Vec<u8>,
}
impl<R: Clone> From<Key<R>> for KeyData {
    fn from(value: Key<R>) -> Self {
        Self {
            id: value.id,
            algorithm: value.algorithm,
            data: value.data,
            timestamp: value.timestamp,
        }
    }
}

#[derive(Debug, Clone, SerializeRepr, DeserializeRepr, Copy, PartialEq, Eq)]
#[repr(u8)]
/// First byte of the encrypted data which indicates the method of encryption.
pub enum Method {
    /// full block with constant memory while making a single left-to-right pass
    ///
    /// Header is represented as:
    ///
    /// | Method | Key ID | Nonce
    Block = 0,
    /// streamed with a constant block size using the STREAM method as described by
    /// [Online Authenticated-Encryption and its Nonce-Reuse Misuse-Resistance](https://eprint.iacr.org/2015/189.pdf)
    ///
    /// Header is represented as:
    ///
    /// | Method | Key ID | Block Size | Nonce Prefix
    Stream = 1,
}
impl Method {
    fn parse(cursor: &mut BytesMut) -> Result<Self, DecryptError> {
        if cursor.remaining() < 1 {
            return Err(DecryptError::Malformed("ciphertext too short".into()));
        }
        Method::try_from(cursor.get_u8()).map_err(DecryptError::Malformed)
    }

    fn header_len(&self, algorithm: Algorithm) -> usize {
        match self {
            // method + key id + nonce
            Method::Block => Method::len() + key_id_len() + algorithm.nonce_len(),
            // method + key id + block size in kilobytes + nonce prefix
            Method::Stream => {
                Method::len() + key_id_len() + SegmentSize::len() + algorithm.nonce_prefix_len()
            }
        }
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
impl From<Method> for usize {
    fn from(method: Method) -> Self {
        method as usize
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

#[cfg(test)]
mod tests {
    use super::*;
    // use crate::rand::*;
    #[test]
    fn test_encrypt_produces_correct_header() -> Result<(), Box<dyn std::error::Error>> {
        let ks = Aead::new(Algorithm::Aes256Gcm)?;
        let k = ks.primary_key()?;
        let cleartext = b"hello world";
        let additional_data = b"additional data";
        let mut res = ks.encrypt(cleartext[..].into(), additional_data)?;
        assert_eq!(
            res.len(),
            1 + 4 + k.algorithm.nonce_len() + cleartext.len() + k.algorithm.tag_len()
        );
        assert_eq!(res.get_u8(), Method::Block as u8);
        assert_eq!(res.get_u32(), ks.primary_key_id());
        assert_eq!(
            res.remaining(),
            k.algorithm.nonce_len() + cleartext.len() + k.algorithm.tag_len()
        );
        Ok(())
    }
    #[test]
    fn test_encrypt_selects_primary_key() -> Result<(), Box<dyn std::error::Error>> {
        let mut ks = Aead::new(Algorithm::Aes256Gcm)?;
        let k = ks.primary_key()?;
        let cleartext = b"hello world";
        let additional_data = b"additional data";
        let mut res = ks.encrypt(cleartext[..].into(), additional_data)?;
        assert_eq!(res.get_u8(), Method::Block as u8);
        assert_eq!(res.get_u32(), ks.primary_key_id());
        assert_eq!(
            res.remaining(),
            k.algorithm.nonce_len() + cleartext.len() + k.algorithm.tag_len()
        );
        Ok(())
    }
}
