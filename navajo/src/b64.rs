pub(crate) mod standard {
    #[cfg(not(feature="std"))]
    use alloc::{string::String, vec::Vec};
    use base64::{engine::general_purpose, Engine as _};
    use serde::{self, Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(input: &[u8], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let encoded: String = general_purpose::STANDARD_NO_PAD.encode(input);
        serializer.serialize_str(&encoded)
    }

    // The signature of a deserialize_with function must follow the pattern:
    //
    //    fn deserialize<'de, D>(D) -> Result<T, D::Error>
    //    where
    //        D: Deserializer<'de>
    //
    // although it may also be generic over the output types T.
    pub fn deserialize<'de, D, T>(deserializer: D) -> Result<T, D::Error>
    where
        D: Deserializer<'de>,
        T: From<Vec<u8>>,
    {
        let s = String::deserialize(deserializer)?;
        general_purpose::STANDARD_NO_PAD
            .decode(s.as_bytes())
            .map(Into::into)
            .map_err(serde::de::Error::custom)
    }
}
