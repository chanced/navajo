use core::ops::{
    Deref, Index, Range, RangeFrom, RangeFull, RangeInclusive, RangeTo, RangeToInclusive,
};

use crate::b64;
use alloc::{sync::Arc, vec::Vec};
use generic_array::{ArrayLength, GenericArray};
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop};

#[derive(Clone, Serialize, Deserialize)]
pub struct Bytes(#[serde(with = "b64::url_safe")] Arc<[u8]>);

impl Bytes {
    pub fn new(bytes: &[u8]) -> Self {
        Self(Arc::from(bytes))
    }
    pub fn as_slice(&self) -> &[u8] {
        &self.0
    }
    pub fn as_vec(self) -> Vec<u8> {
        self.0.as_ref().into()
    }
}
impl Index<usize> for Bytes {
    type Output = u8;
    fn index(&self, index: usize) -> &Self::Output {
        &self.0[index]
    }
}
impl Index<Range<usize>> for Bytes {
    type Output = [u8];
    fn index(&self, index: Range<usize>) -> &Self::Output {
        &self.0[index]
    }
}
impl Index<RangeTo<usize>> for Bytes {
    type Output = [u8];

    fn index(&self, index: RangeTo<usize>) -> &Self::Output {
        &self.0[index]
    }
}
impl Index<RangeFrom<usize>> for Bytes {
    type Output = [u8];
    fn index(&self, index: RangeFrom<usize>) -> &Self::Output {
        &self.0[index]
    }
}
impl Index<RangeInclusive<usize>> for Bytes {
    type Output = [u8];
    fn index(&self, index: RangeInclusive<usize>) -> &Self::Output {
        &self.0[index]
    }
}
impl Index<RangeToInclusive<usize>> for Bytes {
    type Output = [u8];
    fn index(&self, index: RangeToInclusive<usize>) -> &Self::Output {
        &self.0[index]
    }
}
impl Index<RangeFull> for Bytes {
    type Output = [u8];
    fn index(&self, index: RangeFull) -> &Self::Output {
        &self.0[index]
    }
}

impl core::fmt::Debug for Bytes {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_tuple("Sensitive").field(&"***").finish()
    }
}
impl core::fmt::Display for Bytes {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "***")
    }
}
impl From<&[u8]> for Bytes {
    fn from(bytes: &[u8]) -> Self {
        Self(Arc::from(bytes))
    }
}

impl Default for Bytes {
    fn default() -> Self {
        Self(Arc::from([]))
    }
}

impl From<Vec<u8>> for Bytes {
    fn from(bytes: Vec<u8>) -> Self {
        Self(Arc::from(bytes))
    }
}

impl Deref for Bytes {
    type Target = [u8];
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl PartialEq for Bytes {
    fn eq(&self, other: &Self) -> bool {
        self.0 == other.0
    }
}
impl Eq for Bytes {}
impl AsRef<[u8]> for Bytes {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl Zeroize for Bytes {
    fn zeroize(&mut self) {
        self.0 = Arc::from([]);
    }
}

impl Drop for Bytes {
    fn drop(&mut self) {
        if let Some(bytes) = Arc::get_mut(&mut self.0) {
            bytes.zeroize();
        }
    }
}
impl core::hash::Hash for Bytes {
    fn hash<H: core::hash::Hasher>(&self, state: &mut H) {
        self.0.hash(state);
    }
}

impl<const N: usize> TryFrom<Bytes> for [u8; N] {
    type Error = Bytes;
    fn try_from(bytes: Bytes) -> Result<Self, Self::Error> {
        if bytes.len() == N {
            let mut array = [0u8; N];
            array.copy_from_slice(&bytes);
            Ok(array)
        } else {
            Err(bytes)
        }
    }
}

impl ZeroizeOnDrop for Bytes {}

impl<N> TryInto<GenericArray<u8, N>> for Bytes
where
    N: ArrayLength<u8>,
{
    type Error = Bytes;
    fn try_into(self) -> Result<GenericArray<u8, N>, Self::Error> {
        if self.len() == N::to_usize() {
            let mut array = GenericArray::default();
            array.copy_from_slice(&self);
            Ok(array)
        } else {
            Err(self)
        }
    }
}
impl<N> TryInto<GenericArray<u8, N>> for &Bytes
where
    N: ArrayLength<u8>,
{
    type Error = Bytes;

    fn try_into(self) -> Result<GenericArray<u8, N>, Self::Error> {
        if self.len() == N::to_usize() {
            let mut array = GenericArray::default();
            array.copy_from_slice(self);
            Ok(array)
        } else {
            Err(self.clone())
        }
    }
}
