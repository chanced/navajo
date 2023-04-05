use alloc::vec::Vec;
use serde::{Deserialize, Serialize};
use zeroize::ZeroizeOnDrop;

use crate::sensitive;

#[derive(Clone, ZeroizeOnDrop, Debug, Eq, PartialEq)]
pub(super) struct KeyPair {
    pub(super) private: sensitive::Bytes,
    pub(super) public: sensitive::Bytes,
}
#[derive(Serialize, Deserialize)]
struct KeyPairData(sensitive::Bytes, sensitive::Bytes);

impl<'de> Deserialize<'de> for KeyPair {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let KeyPairData(private, public) = Deserialize::deserialize(deserializer)?;
        Ok(Self { private, public })
    }
}
impl Serialize for KeyPair {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let data = KeyPairData(self.private.clone(), self.public.clone());
        data.serialize(serializer)
    }
}

impl KeyPair {
    pub(super) fn concat(&self) -> Vec<u8> {
        [self.private.as_ref(), self.public.as_ref()].concat()
    }
}
