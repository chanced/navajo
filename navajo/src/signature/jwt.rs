use alloc::borrow::Cow;
use serde::{Deserialize, Serialize};

use super::Algorithm;

#[derive(Clone, Debug)]
pub struct Header<'a> {
    pub algorithm: Algorithm,
    pub key_id: Option<Cow<'a, String>>,
}

impl Serialize for Header<'_> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeStruct;

        let mut state = serializer.serialize_struct("Header", 2)?;
        state.serialize_field("alg", &self.algorithm)?;
        state.serialize_field("kid", &self.key_id)?;
        state.end()
    }
}

impl<'de> Deserialize<'de> for Header<'static> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct HeaderData {
            alg: Algorithm,
            kid: Option<String>,
        }
        let HeaderData { alg, kid } = HeaderData::deserialize(deserializer)?;
        Ok(Self {
            algorithm: alg,
            key_id: kid.map(Cow::Owned),
        })
    }
}
