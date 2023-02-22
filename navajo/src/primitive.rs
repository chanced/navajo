use core::{fmt::Display, str::FromStr};

use serde::{Deserialize, Serialize};
use serde_json::{value::RawValue, Value};

use crate::{
    aead, daead,
    envelope::is_cleartext,
    error::{OpenError, SealError},
    keyring::Keyring,
    mac, sig, Aead, Daead, Envelope, Mac, Signature,
};
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]

pub enum Kind {
    #[serde(rename = "AEAD")]
    Aead,
    #[serde(rename = "DAEAD")]
    Daead,
    // #[serde(rename="HPKE")] // TODO: Enable this once HPKE is implemented
    // Hpke,
    #[serde(rename = "MAC")]
    Mac,
    #[serde(rename = "Signature")]
    Signature,
}

impl Kind {
    pub fn as_str(&self) -> &'static str {
        match self {
            Kind::Aead => "AEAD",
            Kind::Daead => "DAEAD",
            // PrimitiveType::Hpke => "HPKE",
            Kind::Mac => "MAC",
            Kind::Signature => "Signature",
        }
    }
    pub fn as_u8(&self) -> u8 {
        match self {
            Kind::Aead => 0,
            Kind::Daead => 1,
            // PrimitiveType::Hpke => 2,
            Kind::Mac => 3,
            Kind::Signature => 4,
        }
    }
}

impl FromStr for Kind {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_uppercase().as_str() {
            "AEAD" => Ok(Kind::Aead),
            "DAEAD" => Ok(Kind::Daead),
            // "HPKE" => Ok(PrimitiveType::Hpke),
            "MAC" => Ok(Kind::Mac),
            "SIGNATURE" => Ok(Kind::Signature),
            _ => Err(format!("invalid primitive type: \"{s}\"")),
        }
    }
}
impl Display for Kind {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}
impl From<Kind> for u8 {
    fn from(pt: Kind) -> Self {
        pt.as_u8()
    }
}

impl TryFrom<u8> for Kind {
    type Error = String;
    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Kind::Aead),
            1 => Ok(Kind::Daead),
            // 2 => Ok(PrimitiveType::Hpke),
            3 => Ok(Kind::Mac),
            4 => Ok(Kind::Signature),
            _ => Err(format!("invalid primitive type: \"{value}\"")),
        }
    }
}

pub enum Primitive {
    Aead(Aead),
    Daead(Daead),
    // Hpke(Hpke) // TODO: Enable this when HPKE is implemented
    Mac(Mac),
    Signature(Signature),
}
impl Primitive {
    pub async fn seal<'a, E>(
        &self,
        associated_data: &[u8],
        envelope: &E,
    ) -> Result<Vec<u8>, SealError>
    where
        E: Envelope + 'static,
    {
        if is_cleartext(envelope) {
            self.serialize_cleartext()
        } else {
            let mut res = vec![self.kind().as_u8()];
            let sealed = match self {
                Primitive::Aead(aead) => aead.keyring().seal(associated_data, envelope).await?,
                Primitive::Daead(daead) => daead.keyring().seal(associated_data, envelope).await?,
                Primitive::Mac(mac) => mac.keyring().seal(associated_data, envelope).await?,
                Primitive::Signature(sig) => sig.keyring().seal(associated_data, envelope).await?,
            };
            res.extend(sealed.into_iter());
            Ok(res)
        }
    }
    pub fn seal_sync<E>(&self, associated_data: &[u8], envelope: &E) -> Result<Vec<u8>, SealError>
    where
        E: Envelope + 'static,
    {
        if is_cleartext(envelope) {
            self.serialize_cleartext()
        } else {
            let mut res = vec![self.kind().as_u8()];
            let sealed = match self {
                Primitive::Aead(aead) => aead.keyring().seal_sync(associated_data, envelope)?,
                Primitive::Daead(daead) => daead.keyring().seal_sync(associated_data, envelope)?,
                Primitive::Mac(mac) => mac.keyring().seal_sync(associated_data, envelope)?,
                Primitive::Signature(sig) => sig.keyring().seal_sync(associated_data, envelope)?,
            };
            res.extend(sealed.into_iter());
            Ok(res)
        }
    }
    pub async fn open<E>(
        associated_data: &[u8],
        keyring_data: &[u8],
        envelope: &E,
    ) -> Result<Self, OpenError>
    where
        E: Envelope + 'static,
    {
        if keyring_data.is_empty() {
            return Err("keyring data is empty".into());
        }

        if is_cleartext(envelope) {
            Self::deserialize_cleartext(keyring_data)
        } else {
            let kind = Kind::try_from(keyring_data[0])?;
            let keyring_data = &keyring_data[1..];
            match kind {
                Kind::Aead => {
                    let keyring =
                        Keyring::<aead::Material>::open(associated_data, keyring_data, envelope)
                            .await?;
                    Ok(Self::Aead(Aead::from_keyring(keyring)))
                }
                Kind::Daead => {
                    let keyring =
                        Keyring::<daead::Material>::open(associated_data, keyring_data, envelope)
                            .await?;
                    Ok(Self::Daead(Daead::from_keyring(keyring)))
                }
                Kind::Mac => {
                    let keyring =
                        Keyring::<mac::Material>::open(associated_data, keyring_data, envelope)
                            .await?;
                    Ok(Self::Mac(Mac::from_keyring(keyring)))
                }
                Kind::Signature => {
                    let keyring =
                        Keyring::<sig::Material>::open(associated_data, keyring_data, envelope)
                            .await?;
                    Ok(Self::Signature(Signature::from_keyring(keyring)))
                }
            }
        }
    }

    pub fn open_sync<E>(
        associated_data: &[u8],
        keyring_data: &[u8],
        envelope: &E,
    ) -> Result<Self, OpenError>
    where
        E: Envelope + 'static,
    {
        if keyring_data.is_empty() {
            return Err("keyring data is empty".into());
        }
        if is_cleartext(envelope) {
            Self::deserialize_cleartext(keyring_data)
        } else {
            let kind = Kind::try_from(keyring_data[0])?;
            let keyring_data = &keyring_data[1..];
            match kind {
                Kind::Aead => {
                    let keyring = Keyring::<aead::Material>::open_sync(
                        associated_data,
                        keyring_data,
                        envelope,
                    )?;
                    Ok(Self::Aead(Aead::from_keyring(keyring)))
                }
                Kind::Daead => {
                    let keyring = Keyring::<daead::Material>::open_sync(
                        associated_data,
                        keyring_data,
                        envelope,
                    )?;
                    Ok(Self::Daead(Daead::from_keyring(keyring)))
                }
                Kind::Mac => {
                    let keyring = Keyring::<mac::Material>::open_sync(
                        associated_data,
                        keyring_data,
                        envelope,
                    )?;
                    Ok(Self::Mac(Mac::from_keyring(keyring)))
                }
                Kind::Signature => {
                    let keyring = Keyring::<sig::Material>::open_sync(
                        associated_data,
                        keyring_data,
                        envelope,
                    )?;
                    Ok(Self::Signature(Signature::from_keyring(keyring)))
                }
            }
        }
    }

    pub fn kind(&self) -> Kind {
        match self {
            Primitive::Aead(_) => Kind::Aead,
            Primitive::Daead(_) => Kind::Daead,
            Primitive::Mac(_) => Kind::Mac,
            Primitive::Signature(_) => Kind::Signature,
        }
    }
    pub fn aead(self) -> Option<Aead> {
        match self {
            Primitive::Aead(aead) => Some(aead),
            _ => None,
        }
    }
    pub fn daead(self) -> Option<Daead> {
        match self {
            Primitive::Daead(daead) => Some(daead),
            _ => None,
        }
    }
    pub fn mac(self) -> Option<Mac> {
        match self {
            Primitive::Mac(mac) => Some(mac),
            _ => None,
        }
    }
    pub fn signature(self) -> Option<Signature> {
        match self {
            Primitive::Signature(sig) => Some(sig),
            _ => None,
        }
    }
    fn deserialize_cleartext(value: &[u8]) -> Result<Self, OpenError> {
        let data: PrimitiveData = serde_json::from_slice(value)?;
        match data.kind {
            Kind::Aead => {
                let keyring: Keyring<aead::Material> = serde_json::from_value(data.keyring)?;
                Ok(Primitive::Aead(Aead::from_keyring(keyring)))
            }
            Kind::Daead => {
                let keyring: Keyring<daead::Material> = serde_json::from_value(data.keyring)?;
                Ok(Primitive::Daead(Daead::from_keyring(keyring)))
            }
            Kind::Mac => {
                let keyring: Keyring<mac::Material> = serde_json::from_value(data.keyring)?;
                Ok(Primitive::Mac(Mac::from_keyring(keyring)))
            }
            Kind::Signature => {
                let keyring: Keyring<sig::Material> = serde_json::from_value(data.keyring)?;
                Ok(Primitive::Signature(Signature::from_keyring(keyring)))
            }
        }
    }

    fn serialize_cleartext(&self) -> Result<Vec<u8>, SealError> {
        let keyring = match self {
            Primitive::Aead(aead) => serde_json::to_value(aead.keyring())?,
            Primitive::Daead(daead) => serde_json::to_value(daead.keyring())?,
            Primitive::Mac(mac) => serde_json::to_value(mac.keyring())?,
            Primitive::Signature(sig) => serde_json::to_value(sig.keyring())?,
        };
        let data = PrimitiveData {
            kind: self.kind(),
            keyring,
        };
        serde_json::to_vec(&data).map_err(|e| SealError(e.to_string()))
    }
}
#[derive(Serialize, Deserialize)]
struct PrimitiveData {
    #[serde(rename = "kind")]
    kind: Kind,
    keyring: Value,
}

#[cfg(test)]
mod tests {
    use crate::{envelope::InMemory, Aead};

    use super::*;

    #[test]
    fn test_in_mem_seal_open() {
        let envelope = InMemory::new();
    }
}
