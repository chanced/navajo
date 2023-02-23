use core::{fmt::Display, str::FromStr};

use serde::{Deserialize, Serialize};
use serde_json::{value::RawValue, Value};

use crate::{
    aead, daead,
    envelope::is_cleartext,
    error::{OpenError, SealError},
    keyring::{open_keyring_value, open_keyring_value_sync, Keyring},
    mac, sig, Aad, Aead, Daead, Envelope, Mac, Signature,
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
    pub async fn seal<'a, A, E>(&self, aad: Aad<A>, envelope: &E) -> Result<Vec<u8>, SealError>
    where
        A: AsRef<[u8]> + Send + Sync,
        E: Envelope + 'static,
    {
        if is_cleartext(envelope) {
            self.serialize_cleartext()
        } else {
            let sealed = match self {
                Primitive::Aead(aead) => aead.keyring().seal(aad, envelope).await?,
                Primitive::Daead(daead) => daead.keyring().seal(aad, envelope).await?,
                Primitive::Mac(mac) => mac.keyring().seal(aad, envelope).await?,
                Primitive::Signature(sig) => sig.keyring().seal(aad, envelope).await?,
            };
            Ok(sealed)
        }
    }
    pub fn seal_sync<A, E>(&self, aad: Aad<A>, envelope: &E) -> Result<Vec<u8>, SealError>
    where
        A: AsRef<[u8]>,
        E: Envelope + 'static,
    {
        if is_cleartext(envelope) {
            self.serialize_cleartext()
        } else {
            let mut res = vec![self.kind().as_u8()];
            let sealed = match self {
                Primitive::Aead(aead) => aead.keyring().seal_sync(aad, envelope)?,
                Primitive::Daead(daead) => daead.keyring().seal_sync(aad, envelope)?,
                Primitive::Mac(mac) => mac.keyring().seal_sync(aad, envelope)?,
                Primitive::Signature(sig) => sig.keyring().seal_sync(aad, envelope)?,
            };
            res.extend(sealed.into_iter());
            Ok(res)
        }
    }
    pub async fn open<A, C, E>(aad: Aad<A>, ciphertext: C, envelope: &E) -> Result<Self, OpenError>
    where
        A: AsRef<[u8]> + Send + Sync,
        C: AsRef<[u8]> + Send + Sync,
        E: Envelope + 'static,
    {
        if ciphertext.as_ref().is_empty() {
            return Err("keyring data is empty".into());
        }
        if is_cleartext(envelope) {
            Self::deserialize_cleartext(ciphertext.as_ref())
        } else {
            let (kind, value) = open_keyring_value(aad, ciphertext, envelope).await?;
            Self::open_value(kind, value)
        }
    }

    pub fn open_sync<A, C, E>(aad: Aad<A>, ciphertext: C, envelope: &E) -> Result<Self, OpenError>
    where
        A: AsRef<[u8]>,
        C: AsRef<[u8]>,
        E: Envelope + 'static,
    {
        let sealed = ciphertext.as_ref();
        if sealed.is_empty() {
            return Err("keyring data is empty".into());
        }

        if is_cleartext(envelope) {
            Self::deserialize_cleartext(sealed)
        } else {
            let (kind, value) = open_keyring_value_sync(aad, sealed, envelope)?;
            Self::open_value(kind, value)
        }
    }
    fn open_value(kind: Kind, value: Value) -> Result<Self, OpenError> {
        match kind {
            Kind::Aead => {
                let keyring: Keyring<aead::Material> = serde_json::from_value(value)?;
                Ok(Self::Aead(Aead::from_keyring(keyring)))
            }
            Kind::Daead => {
                let keyring: Keyring<daead::Material> = serde_json::from_value(value)?;
                Ok(Self::Daead(Daead::from_keyring(keyring)))
            }
            Kind::Mac => {
                let keyring: Keyring<mac::Material> = serde_json::from_value(value)?;
                Ok(Self::Mac(Mac::from_keyring(keyring)))
            }
            Kind::Signature => {
                let keyring: Keyring<sig::Material> = serde_json::from_value(value)?;
                Ok(Self::Signature(Signature::from_keyring(keyring)))
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
        let value: Value = serde_json::from_slice(value)?;
        println!(
            "\n\nvalue: {}\n\n",
            serde_json::to_string_pretty(&value).unwrap()
        );
        let data: PrimitiveData = serde_json::from_value(value)?;

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
    use crate::envelope::InMemory;

    use super::*;

    #[cfg(feature = "mac")]
    #[tokio::test]
    async fn test_in_mem_seal_open_mac() {
        let mac = mac::Mac::new(mac::Algorithm::Sha256, None);
        let primary_key = mac.primary_key();
        // in a real application, you would use a real key management service.
        // InMemory is only suitable for testing.
        let in_mem = InMemory::default();
        let data = Mac::seal(&mac, Aad::empty(), &in_mem).await.unwrap();
        let mac = Mac::open(Aad::empty(), &data, &in_mem).await.unwrap();
        assert_eq!(mac.primary_key(), primary_key);
    }
}
