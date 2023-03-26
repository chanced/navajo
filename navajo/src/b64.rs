pub(crate) mod url_safe {
    #[cfg(not(feature = "std"))]
    use alloc::{string::String, vec::Vec};
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
    use serde::{self, Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(input: &[u8], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let encoded: String = URL_SAFE_NO_PAD.encode(input);
        serializer.serialize_str(&encoded)
    }

    pub fn deserialize<'de, D, T>(deserializer: D) -> Result<T, D::Error>
    where
        D: Deserializer<'de>,
        T: From<Vec<u8>>,
    {
        let s = String::deserialize(deserializer)?;
        URL_SAFE_NO_PAD
            .decode(s.as_bytes())
            .map(Into::into)
            .map_err(serde::de::Error::custom)
    }
}
pub(crate) mod optional_url_safe {
    #[cfg(not(feature = "std"))]
    use alloc::{string::String, vec::Vec};
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
    use serde::{self, Deserialize, Deserializer, Serializer};

    pub fn serialize<S, T>(input: &Option<T>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
        T: AsRef<[u8]>,
    {
        if input.is_none() {
            return serializer.serialize_none();
        }
        serializer.serialize_str(&URL_SAFE_NO_PAD.encode(input.as_ref().unwrap().as_ref()))
    }

    pub fn deserialize<'de, D, T>(deserializer: D) -> Result<T, D::Error>
    where
        D: Deserializer<'de>,
        T: From<Option<Vec<u8>>>,
    {
        let val = Option::<String>::deserialize(deserializer)?;
        let val = val
            .map(|val| {
                URL_SAFE_NO_PAD
                    .decode(val)
                    .map_err(serde::de::Error::custom)
            })
            .transpose()?;
        Ok(val.into())
    }
}

pub(crate) mod optional_seq_url_safe {
    #[cfg(not(feature = "std"))]
    use alloc::{string::String, vec::Vec};
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
    use serde::{self, ser::SerializeSeq, Deserialize, Deserializer, Serializer};

    pub fn serialize<S, V, T>(input: &Option<T>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
        T: AsRef<[V]>,
        V: AsRef<[u8]>,
    {
        if input.is_none() {
            return serializer.serialize_none();
        }
        let input = input.as_ref().unwrap().as_ref();
        let mut ser = serializer.serialize_seq(Some(input.len()))?;
        for item in input {
            ser.serialize_element(&URL_SAFE_NO_PAD.encode(item.as_ref()))?;
        }
        ser.end()
    }

    pub fn deserialize<'de, D, T>(deserializer: D) -> Result<T, D::Error>
    where
        D: Deserializer<'de>,
        T: From<Option<Vec<Vec<u8>>>>,
    {
        let data = Option::<Vec<String>>::deserialize(deserializer)?;
        let data = data
            .map(|data| {
                data.into_iter()
                    .map(|data| {
                        URL_SAFE_NO_PAD
                            .decode(data)
                            .map_err(serde::de::Error::custom)
                    })
                    .collect::<Result<Vec<_>, _>>()
            })
            .transpose()?;
        Ok(data.into())
    }
}

// pub(crate) mod standard {
//     use base64::{engine::general_purpose::STANDARD_NO_PAD, Engine as _};
//     use serde::{self, Deserialize, Deserializer, Serializer};

//     #[cfg(not(feature = "std"))]
//     use alloc::{string::String, vec::Vec};

//     pub fn serialize<S>(input: &[u8], serializer: S) -> Result<S::Ok, S::Error>
//     where
//         S: Serializer,
//     {
//         let encoded: String = STANDARD_NO_PAD.encode(input);
//         serializer.serialize_str(&encoded)
//     }
//     pub fn deserialize<'de, D, T>(deserializer: D) -> Result<T, D::Error>
//     where
//         D: Deserializer<'de>,
//         T: From<Vec<u8>>,
//     {
//         let s = String::deserialize(deserializer)?;
//         STANDARD_NO_PAD
//             .decode(s.as_bytes())
//             .map(Into::into)
//             .map_err(serde::de::Error::custom)
//     }
// }
