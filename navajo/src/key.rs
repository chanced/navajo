use alloc::{format, string::String, sync::Arc};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use zeroize::ZeroizeOnDrop;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(try_from = "i8", into = "i8")]
#[repr(i8)]
pub enum KeyStatus {
    /// Indicates that the key is active and the primary key in the keyring. It
    /// will be used, by default, for encryption.
    ///
    /// The key will be used for decryption when aplicable (i.e. ciphertext
    /// encrypted with it).
    Primary = 0,
    /// The indicates that the key is active and can be used for encryption if
    /// specified.
    ///
    /// The key will be used for decryption when applicable (i.e. ciphertext
    /// encrypted with it).
    Secondary = 1,

    /// Indicates that the key is disabled and cannot be used for encryption
    /// except for [daead] queries. It can still be used to decrypt applicable
    /// ciphertext.
    Disabled = -1,
}

impl Default for KeyStatus {
    fn default() -> Self {
        Self::Secondary
    }
}
impl KeyStatus {
    /// Returns `true` if `Primary`.
    pub fn is_primary(&self) -> bool {
        *self == Self::Primary
    }
    pub fn is_secondary(&self) -> bool {
        *self == Self::Secondary
    }

    /// Returns `true` if `Disabled`.
    pub fn is_disabled(&self) -> bool {
        matches!(self, Self::Disabled)
    }
}

impl TryFrom<i8> for KeyStatus {
    type Error = String;
    fn try_from(i: i8) -> Result<Self, Self::Error> {
        match i {
            0 => Ok(Self::Primary),
            1 => Ok(Self::Secondary),
            -1 => Ok(Self::Disabled),
            _ => Err(format!("invalid key status: {}", i)),
        }
    }
}

impl From<KeyStatus> for i8 {
    fn from(s: KeyStatus) -> Self {
        s as i8
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
/// Metadata for a particular key.
pub struct KeyInfo<A> {
    id: u32,
    status: KeyStatus,
    algorithm: A,
}

pub(crate) trait KeyMaterial:
    Send + Sync + ZeroizeOnDrop + Clone + 'static + PartialEq + Eq
{
    type Algorithm: PartialEq + Eq;
    fn algorithm(&self) -> Self::Algorithm;
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct Key<M>
where
    M: KeyMaterial,
{
    pub(crate) id: u32,
    pub(crate) status: KeyStatus,
    pub(crate) material: Arc<M>,
    pub(crate) meta: Option<Value>,
}
impl<M> Key<M>
where
    M: KeyMaterial,
{
    pub(crate) fn new(
        id: u32,
        status: KeyStatus,
        material: M,
        meta: Option<serde_json::Value>,
    ) -> Self {
        Self {
            id,
            status,
            material: Arc::new(material),
            meta,
        }
    }
    pub(crate) fn info(&self) -> KeyInfo<M::Algorithm>
    where
        M: KeyMaterial,
    {
        KeyInfo {
            id: self.id,
            status: self.status,
            algorithm: self.material.algorithm(),
        }
    }
    pub(crate) fn algorithm(&self) -> M::Algorithm
    where
        M: KeyMaterial,
    {
        self.material.algorithm()
    }
    pub fn status(&self) -> KeyStatus {
        self.status
    }
    pub(crate) fn material(&self) -> &M {
        &self.material
    }
}
impl<M> PartialEq for Key<M>
where
    M: KeyMaterial,
{
    fn eq(&self, other: &Self) -> bool {
        self.id == other.id && self.material == other.material
    }
}
