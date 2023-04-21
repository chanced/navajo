use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(untagged)]
pub enum KeyringInfo {
    #[cfg(feature = "aead")]
    Aead(crate::aead::KeyringInfo),
    #[cfg(feature = "daead")]
    Daead(crate::daead::KeyringInfo),
    // Hpke(Hpke) // TODO: Enable this when HPKE is implemented
    #[cfg(feature = "mac")]
    Mac(crate::mac::KeyringInfo),
    #[cfg(feature = "dsa")]
    Dsa(crate::dsa::KeyringInfo),
}
impl From<&super::Primitive> for KeyringInfo {
    fn from(primitive: &super::Primitive) -> Self {
        use super::Primitive::*;
        match primitive {
            #[cfg(feature = "aead")]
            Aead(keyring) => Self::Aead(keyring.info()),
            #[cfg(feature = "daead")]
            Daead(keyring) => Self::Daead(keyring.info()),
            // Hpke(keyring) => Self::Hpke(keyring.into()),
            #[cfg(feature = "mac")]
            Mac(keyring) => Self::Mac(keyring.info()),
            #[cfg(feature = "dsa")]
            Dsa(keyring) => Self::Dsa(keyring.info()),
        }
    }
}

impl KeyringInfo {
    pub fn kind(&self) -> super::Kind {
        use super::Kind::*;
        match self {
            #[cfg(feature = "aead")]
            Self::Aead(_) => Aead,
            #[cfg(feature = "daead")]
            Self::Daead(_) => Daead,
            // Self::Hpke(_) => Hpke,
            #[cfg(feature = "mac")]
            Self::Mac(_) => Mac,
            #[cfg(feature = "dsa")]
            Self::Dsa(_) => Dsa,
        }
    }
    pub fn version(&self) -> u8 {
        match self {
            #[cfg(feature = "aead")]
            Self::Aead(info) => info.version,
            #[cfg(feature = "daead")]
            Self::Daead(info) => info.version,
            // Self::Hpke(info) => info.version,
            #[cfg(feature = "mac")]
            Self::Mac(info) => info.version,
            #[cfg(feature = "dsa")]
            Self::Dsa(info) => info.version,
        }
    }
    #[cfg(feature = "aead")]
    pub fn aead(&self) -> Option<crate::aead::KeyringInfo> {
        if let Self::Aead(info) = self {
            Some(info.clone())
        } else {
            None
        }
    }
    #[cfg(feature = "daead")]
    pub fn daead(&self) -> Option<crate::daead::KeyringInfo> {
        if let Self::Daead(info) = self {
            Some(info.clone())
        } else {
            None
        }
    }
    #[cfg(feature = "dsa")]
    pub fn dsa(&self) -> Option<crate::dsa::KeyringInfo> {
        if let Self::Dsa(info) = self {
            Some(info.clone())
        } else {
            None
        }
    }
    #[cfg(feature = "mac")]
    pub fn mac(&self) -> Option<crate::mac::KeyringInfo> {
        if let Self::Mac(info) = self {
            Some(info.clone())
        } else {
            None
        }
    }
}

impl<'de> Deserialize<'de> for KeyringInfo {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        // hmm... not sure I like this.
        let generic: crate::KeyringInfo<serde_json::Value> =
            Deserialize::deserialize(deserializer)?;
        match generic.kind {
            #[cfg(feature = "aead")]
            crate::Kind::Aead => Ok(Self::Aead(crate::KeyringInfo {
                version: generic.version,
                keys: generic
                    .keys
                    .into_iter()
                    .map(serde_json::from_value)
                    .collect::<Result<Vec<_>, _>>()
                    .map_err(serde::de::Error::custom)?,
                kind: generic.kind,
            })),
            #[cfg(feature = "daead")]
            crate::Kind::Daead => Ok(Self::Daead(crate::KeyringInfo {
                version: generic.version,
                keys: generic
                    .keys
                    .into_iter()
                    .map(serde_json::from_value)
                    .collect::<Result<Vec<_>, _>>()
                    .map_err(serde::de::Error::custom)?,
                kind: generic.kind,
            })),
            #[cfg(feature = "mac")]
            crate::Kind::Mac => Ok(Self::Mac(crate::KeyringInfo {
                version: generic.version,
                keys: generic
                    .keys
                    .into_iter()
                    .map(serde_json::from_value)
                    .collect::<Result<Vec<_>, _>>()
                    .map_err(serde::de::Error::custom)?,
                kind: generic.kind,
            })),
            #[cfg(feature = "dsa")]
            crate::Kind::Dsa => Ok(Self::Dsa(crate::KeyringInfo {
                version: generic.version,
                keys: generic
                    .keys
                    .into_iter()
                    .map(serde_json::from_value)
                    .collect::<Result<Vec<_>, _>>()
                    .map_err(serde::de::Error::custom)?,
                kind: generic.kind,
            })),
        }
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;
    use strum::IntoEnumIterator;

    use crate::{Metadata, Primitive};

    use super::*;

    #[test]
    fn test_keyring_info_serde() {
        let metadata: Metadata = json!({"use": "sign"}).try_into().unwrap();
        for kind in crate::primitive::Kind::iter() {
            match kind {
                crate::Kind::Aead => {
                    let mut keyring = crate::aead::Aead::new(
                        crate::aead::Algorithm::Aes256Gcm,
                        Some(metadata.clone()),
                    );
                    keyring.add(
                        crate::aead::Algorithm::XChaCha20Poly1305,
                        Some(metadata.clone()),
                    );
                    let primitive: Primitive = (&keyring).into();
                    let info = primitive.info();
                    assert!(
                        matches!(info, KeyringInfo::Aead(_)),
                        "expected kind {kind}, got {:?}",
                        info
                    );
                    let aead_info = info.aead().unwrap();
                    for key in aead_info.keys.iter() {
                        assert_eq!(key.metadata, Some(metadata.clone()));
                    }
                    assert_eq!(aead_info.keys.len(), 2);

                    let serialized = serde_json::to_string(&info).unwrap();
                    let deserialized: KeyringInfo = serde_json::from_str(&serialized).unwrap();
                    assert_eq!(info, deserialized);
                }
                crate::Kind::Daead => {
                    let mut keyring = crate::daead::Daead::new(
                        crate::daead::Algorithm::Aes256Siv,
                        Some(metadata.clone()),
                    );
                    keyring.add(crate::daead::Algorithm::Aes256Siv, Some(metadata.clone()));
                    let primitive: Primitive = (&keyring).into();
                    let info = primitive.info();
                    assert!(
                        matches!(info, KeyringInfo::Daead(_)),
                        "expected kind {kind}, got {:?}",
                        info
                    );
                    let daead_info = info.daead().unwrap();
                    assert_eq!(daead_info.keys.len(), 2);
                    for key in daead_info.keys.iter() {
                        assert_eq!(key.metadata, Some(metadata.clone()));
                    }

                    let serialized = serde_json::to_string(&info).unwrap();
                    let deserialized: KeyringInfo = serde_json::from_str(&serialized).unwrap();
                    assert_eq!(info, deserialized);
                }
                crate::Kind::Mac => {
                    let mut keyring =
                        crate::mac::Mac::new(crate::mac::Algorithm::Sha256, Some(metadata.clone()));
                    keyring.add(
                        crate::mac::Algorithm::Sha384,
                        Some(json!({"use": "sign"}).try_into().unwrap()),
                    );
                    let primitive: Primitive = (&keyring).into();
                    let info = primitive.info();
                    assert!(
                        matches!(info, KeyringInfo::Mac(_)),
                        "expected kind {kind}, got {:?}",
                        info
                    );
                    let mac_info = info.mac().unwrap();
                    assert_eq!(mac_info.keys.len(), 2);
                    for key in mac_info.keys.iter() {
                        assert_eq!(key.metadata, Some(metadata.clone()));
                    }

                    assert_eq!(mac_info.keys.len(), 2);

                    let serialized = serde_json::to_string(&info).unwrap();
                    let deserialized: KeyringInfo = serde_json::from_str(&serialized).unwrap();
                    assert_eq!(info, deserialized);
                }
                crate::Kind::Dsa => {
                    let mut keyring = crate::dsa::Signer::new(
                        crate::dsa::Algorithm::Ed25519,
                        Some("first_key".into()),
                        Some(metadata.clone()),
                    );
                    keyring
                        .add(
                            crate::dsa::Algorithm::Es256,
                            Some("second_key".into()),
                            Some(json!({"use": "sign"}).try_into().unwrap()),
                        )
                        .unwrap();
                    let primitive: Primitive = (&keyring).into();
                    let info = primitive.info();
                    assert!(
                        matches!(info, KeyringInfo::Dsa(_)),
                        "expected kind {kind}, got {:?}",
                        info
                    );
                    let dsa_key_info = info.dsa().unwrap();
                    assert_eq!(dsa_key_info.keys.len(), 2);
                    for key in dsa_key_info.keys.iter() {
                        assert_eq!(key.metadata, Some(metadata.clone()));
                    }
                    assert_eq!(dsa_key_info.keys[0].pub_id, "first_key");
                    assert_eq!(dsa_key_info.keys[1].pub_id, "second_key");
                    assert_eq!(dsa_key_info.keys.len(), 2);

                    let serialized = serde_json::to_string(&info).unwrap();
                    let deserialized: KeyringInfo = serde_json::from_str(&serialized).unwrap();
                    assert_eq!(info, deserialized);
                }
            }
        }
    }
}

// Dsa(KeyringInfo { version: 0, keys: [KeyInfo { id: 186165665, pub_id: "first_key", status: Primary, pub_key: Sensitive("***"), origin: Navajo, algorithm: Ed25519, metadata: Some(Metadata { key_use: Some(Other("sign")), key_operations: None, additional_fields: {}, known_fields: {"use": String("sign")} }) }, KeyInfo { id: 2993726385, pub_id: "second_key", status: Secondary, pub_key: Sensitive("***"), origin: Navajo, algorithm: Es256, metadata: Some(Metadata { key_use: Some(Other("sign")), key_operations: None, additional_fields: {}, known_fields: {"use": String("sign")} }) }], kind: Dsa })',
