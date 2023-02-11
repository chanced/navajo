use core::ops::Deref;

use alloc::{sync::Arc, vec::Vec};
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop};

#[derive(Clone, Serialize, Deserialize)]
pub(crate) struct SensitiveBytes(pub(crate) Arc<[u8]>);

impl SensitiveBytes {
    pub(crate) fn new(bytes: &[u8]) -> Self {
        Self(Arc::from(bytes))
    }
    pub(crate) fn as_slice(&self) -> &[u8] {
        &self.0
    }
    pub(crate) fn as_vec(self) -> Vec<u8> {
        self.0.as_ref().into()
    }
}
impl core::fmt::Debug for SensitiveBytes {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_tuple("Sensitive").field(&"***").finish()
    }
}
impl core::fmt::Display for SensitiveBytes {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "***")
    }
}
impl From<&[u8]> for SensitiveBytes {
    fn from(bytes: &[u8]) -> Self {
        Self(Arc::from(bytes))
    }
}

impl Default for SensitiveBytes {
    fn default() -> Self {
        Self(Arc::from([]))
    }
}

impl From<Vec<u8>> for SensitiveBytes {
    fn from(bytes: Vec<u8>) -> Self {
        Self(Arc::from(bytes))
    }
}

impl Deref for SensitiveBytes {
    type Target = [u8];
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl PartialEq for SensitiveBytes {
    fn eq(&self, other: &Self) -> bool {
        self.0 == other.0
    }
}
impl Eq for SensitiveBytes {}
impl AsRef<[u8]> for SensitiveBytes {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}
impl Drop for SensitiveBytes {
    fn drop(&mut self) {
        if let Some(bytes) = Arc::get_mut(&mut self.0) {
            bytes.zeroize();
        }
    }
}
impl ZeroizeOnDrop for SensitiveBytes {}
impl Zeroize for SensitiveBytes {
    fn zeroize(&mut self) {
        if let Some(bytes) = Arc::get_mut(&mut self.0) {
            bytes.zeroize();
        }
    }
}
