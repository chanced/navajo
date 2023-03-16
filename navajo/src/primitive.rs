use core::{fmt::Display, str::FromStr};

use alloc::{
    format,
    string::{String, ToString},
    vec,
    vec::Vec,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::{
    envelope::{self, is_plaintext},
    error::{OpenError, SealError},
    keyring::{open_keyring_value, open_keyring_value_sync, Keyring},
    Aad,
    Envelope,
    // mac, signature, Aad, Daead, Envelope, Mac, Signer,
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

pub async fn seal<A, E>(
    primitive: impl Into<Primitive>,
    aad: Aad<A>,
    envelope: &E,
) -> Result<Vec<u8>, SealError>
where
    A: 'static + AsRef<[u8]> + Send + Sync,
    E: 'static + Envelope,
{
    let primitive = primitive.into();
    Primitive::seal(&primitive, aad, envelope).await
}

pub async fn open<A, C, E>(aad: Aad<A>, ciphertext: C, envelope: &E) -> Result<Primitive, OpenError>
where
    A: 'static + AsRef<[u8]> + Send + Sync,
    C: 'static + AsRef<[u8]> + Send + Sync,
    E: 'static + Envelope,
{
    Primitive::open(aad, ciphertext, envelope).await
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
    #[cfg(feature = "aead")]
    Aead(crate::Aead),
    #[cfg(feature = "daead")]
    Daead(crate::Daead),
    // Hpke(Hpke) // TODO: Enable this when HPKE is implemented
    #[cfg(feature = "mac")]
    Mac(crate::Mac),
    #[cfg(feature = "signature")]
    Signature(crate::Signer),
}
impl Primitive {
    pub async fn seal<A, E>(&self, aad: Aad<A>, envelope: &E) -> Result<Vec<u8>, SealError>
    where
        A: 'static + AsRef<[u8]> + Send + Sync,
        E: 'static + Envelope,
    {
        if is_plaintext(envelope) {
            return self.serialize_plaintext();
        }
        let sealed = self.seal_keyring(aad, envelope, vec![0u8; 8]).await?;
        finalize_seal(sealed)
    }

    pub fn seal_sync<'a, A, E>(&'a self, aad: Aad<A>, envelope: &'a E) -> Result<Vec<u8>, SealError>
    where
        A: AsRef<[u8]>,
        E: 'static + envelope::sync::Envelope,
    {
        if is_plaintext(envelope) {
            return self.serialize_plaintext();
        }
        let sealed = self.seal_keyring_sync(aad, envelope, vec![0u8; 8])?;
        finalize_seal(sealed)
    }

    pub async fn open<A, C, E>(aad: Aad<A>, ciphertext: C, envelope: &E) -> Result<Self, OpenError>
    where
        A: 'static + AsRef<[u8]> + Send + Sync,
        C: 'static + AsRef<[u8]> + Send + Sync,
        E: 'static + Envelope,
    {
        let ciphertext = ciphertext.as_ref();
        if ciphertext.is_empty() {
            return Err("keyring data is empty".into());
        }
        if is_plaintext(envelope) {
            return Self::deserialize_cleartext(ciphertext);
        }
        let len = read_len(ciphertext)?;

        // todo: revisit this
        // there is probably a way to avoid copying this into a vec
        let ciphertext = ciphertext[8..len + 8].to_vec();
        let (kind, value) = open_keyring_value(aad, ciphertext, envelope).await?;
        Self::open_value(kind, value)
    }

    pub fn open_sync<A, C, E>(aad: Aad<A>, ciphertext: C, envelope: &E) -> Result<Self, OpenError>
    where
        A: AsRef<[u8]>,
        C: AsRef<[u8]>,
        E: 'static + crate::envelope::sync::Envelope,
    {
        let ciphertext = ciphertext.as_ref();
        if ciphertext.is_empty() {
            return Err("sealed data is empty".into());
        }
        if is_plaintext(envelope) {
            Self::deserialize_cleartext(ciphertext)
        } else {
            let len = read_len(ciphertext)?;
            let (kind, value) = open_keyring_value_sync(aad, &ciphertext[8..len], envelope)?;
            Self::open_value(kind, value)
        }
    }

    fn open_value(kind: Kind, value: Value) -> Result<Self, OpenError> {
        match kind {
            Kind::Aead => {
                #[cfg(feature = "aead")]
                {
                    let keyring: Keyring<crate::aead::Material> = serde_json::from_value(value)?;
                    Ok(Self::Aead(crate::Aead::from_keyring(keyring)))
                }
                #[cfg(not(feature = "aead"))]
                {
                    Err("aead feature is not enabled".into())
                }
            }
            Kind::Daead => {
                #[cfg(feature = "daead")]
                {
                    let keyring: Keyring<crate::daead::Material> = serde_json::from_value(value)?;
                    Ok(Self::Daead(crate::Daead::from_keyring(keyring)))
                }
                #[cfg(not(feature = "daead"))]
                {
                    Err("daead feature is not enabled".into())
                }
            }
            Kind::Mac => {
                #[cfg(feature = "mac")]
                {
                    let keyring: Keyring<crate::mac::Material> = serde_json::from_value(value)?;
                    Ok(Self::Mac(crate::Mac::from_keyring(keyring)))
                }
                #[cfg(not(feature = "mac"))]
                {
                    Err("mac feature is not enabled".into())
                }
            }
            Kind::Signature => {
                #[cfg(feature = "signature")]
                {
                    let keyring: Keyring<crate::signature::Material> =
                        serde_json::from_value(value)?;
                    Ok(Self::Signature(crate::Signer::from_keyring(keyring)))
                }
                #[cfg(not(feature = "signature"))]
                {
                    Err("signature feature is not enabled".into())
                }
            }
        }
    }
    pub fn kind(&self) -> Kind {
        match self {
            #[cfg(feature = "aead")]
            Primitive::Aead(_) => Kind::Aead,
            #[cfg(feature = "daead")]
            Primitive::Daead(_) => Kind::Daead,
            #[cfg(feature = "mac")]
            Primitive::Mac(_) => Kind::Mac,
            #[cfg(feature = "signature")]
            Primitive::Signature(_) => Kind::Signature,
        }
    }
    #[cfg(feature = "aead")]
    pub fn aead(self) -> Option<crate::Aead> {
        match self {
            Primitive::Aead(aead) => Some(aead),
            _ => None,
        }
    }
    #[cfg(feature = "daead")]
    pub fn daead(self) -> Option<crate::Daead> {
        match self {
            Primitive::Daead(daead) => Some(daead),
            _ => None,
        }
    }
    #[cfg(feature = "mac")]
    pub fn mac(self) -> Option<crate::Mac> {
        match self {
            Primitive::Mac(mac) => Some(mac),
            _ => None,
        }
    }
    #[cfg(feature = "signature")]
    pub fn signature(self) -> Option<crate::Signer> {
        match self {
            Primitive::Signature(sig) => Some(sig),
            _ => None,
        }
    }
    fn deserialize_cleartext(value: &[u8]) -> Result<Self, OpenError> {
        let value: Value = serde_json::from_slice(value)?;
        let data: PrimitiveData = serde_json::from_value(value)?;

        match data.kind {
            Kind::Aead => {
                #[cfg(feature = "aead")]
                {
                    let keyring: Keyring<crate::aead::Material> =
                        serde_json::from_value(data.keyring)?;
                    Ok(Primitive::Aead(crate::Aead::from_keyring(keyring)))
                }
                #[cfg(not(feature = "aead"))]
                {
                    Err("aead feature is not enabled".into())
                }
            }
            Kind::Daead => {
                #[cfg(feature = "daead")]
                {
                    let keyring: Keyring<crate::daead::Material> =
                        serde_json::from_value(data.keyring)?;
                    Ok(Primitive::Daead(crate::Daead::from_keyring(keyring)))
                }
                #[cfg(not(feature = "daead"))]
                {
                    Err("daead feature is not enabled".into())
                }
            }
            Kind::Mac => {
                #[cfg(feature = "mac")]
                {
                    let keyring: Keyring<crate::mac::Material> =
                        serde_json::from_value(data.keyring)?;
                    Ok(Primitive::Mac(crate::Mac::from_keyring(keyring)))
                }
                #[cfg(not(feature = "mac"))]
                {
                    Err("mac feature is not enabled".into())
                }
            }
            Kind::Signature => {
                #[cfg(feature = "signature")]
                {
                    let keyring: Keyring<crate::signature::Material> =
                        serde_json::from_value(data.keyring)?;
                    Ok(Primitive::Signature(crate::Signer::from_keyring(keyring)))
                }
                #[cfg(not(feature = "signature"))]
                {
                    Err("signature feature is not enabled".into())
                }
            }
        }
    }

    fn serialize_plaintext(&self) -> Result<Vec<u8>, SealError> {
        let keyring = match self {
            #[cfg(feature = "aead")]
            Primitive::Aead(aead) => serde_json::to_value(aead.keyring())?,
            #[cfg(feature = "daead")]
            Primitive::Daead(daead) => serde_json::to_value(daead.keyring())?,
            #[cfg(feature = "mac")]
            Primitive::Mac(mac) => serde_json::to_value(mac.keyring())?,
            #[cfg(feature = "signature")]
            Primitive::Signature(sig) => serde_json::to_value(sig.keyring())?,
        };
        let data = PrimitiveData {
            kind: self.kind(),
            keyring,
        };
        let mut v = serde_json::to_vec(&data).map_err(|e| SealError(e.to_string()))?;
        v.push(b'\n');
        Ok(v)
    }
    async fn seal_keyring<A, E>(
        &self,
        aad: Aad<A>,
        envelope: &E,
        mut v: Vec<u8>,
    ) -> Result<Vec<u8>, SealError>
    where
        A: 'static + AsRef<[u8]> + Send + Sync,
        E: 'static + Envelope,
    {
        v.append(&mut match self {
            #[cfg(feature = "aead")]
            Primitive::Aead(aead) => aead.keyring().seal(aad, envelope).await?,
            #[cfg(feature = "daead")]
            Primitive::Daead(daead) => daead.keyring().seal(aad, envelope).await?,
            #[cfg(feature = "mac")]
            Primitive::Mac(mac) => mac.keyring().seal(aad, envelope).await?,
            #[cfg(feature = "signature")]
            Primitive::Signature(sig) => sig.keyring().seal(aad, envelope).await?,
        });
        Ok(v)
    }
    fn seal_keyring_sync<A, E>(
        &self,
        aad: Aad<A>,
        envelope: &E,
        mut v: Vec<u8>,
    ) -> Result<Vec<u8>, SealError>
    where
        A: AsRef<[u8]>,
        E: envelope::sync::Envelope,
    {
        v.append(&mut match self {
            #[cfg(feature = "aead")]
            Primitive::Aead(aead) => aead.keyring().seal_sync(aad, envelope)?,
            #[cfg(feature = "daead")]
            Primitive::Daead(daead) => daead.keyring().seal_sync(aad, envelope)?,
            #[cfg(feature = "mac")]
            Primitive::Mac(mac) => mac.keyring().seal_sync(aad, envelope)?,
            #[cfg(feature = "signature")]
            Primitive::Signature(sig) => sig.keyring().seal_sync(aad, envelope)?,
        });
        Ok(v)
    }
}
fn read_len(ciphertext: &[u8]) -> Result<usize, OpenError> {
    if ciphertext.len() <= 8 {
        Err(OpenError("keyring data too short".to_string()))?
    }

    let len = u64::from_be_bytes(
        ciphertext[0..8]
            .try_into()
            .map_err(|_| OpenError("keyring data too short".to_string()))?,
    );
    if ciphertext.as_ref().len() < len as usize + 8 {
        Err(OpenError("keyring data too short".to_string()))?
    }
    if len > usize::MAX as u64 {
        Err(OpenError(
            "keyring data exceeds system len limits".to_string(),
        ))?
    }
    let len = len as usize;
    if ciphertext.len() < len + 8 {
        return Err("invalid keydata".into());
    }

    Ok(len)
}
fn finalize_seal(mut sealed: Vec<u8>) -> Result<Vec<u8>, SealError> {
    let len = sealed.len() - 8;
    let len_bytes = len.to_be_bytes();
    sealed.splice(0..8, len_bytes.into_iter());
    sealed.push(b'\n');
    Ok(sealed)
}

#[derive(Serialize, Deserialize)]
struct PrimitiveData {
    #[serde(rename = "kind")]
    kind: Kind,
    keyring: Value,
}

impl From<crate::Aead> for Primitive {
    fn from(value: crate::Aead) -> Self {
        Primitive::Aead(value)
    }
}
impl From<crate::Daead> for Primitive {
    fn from(value: crate::Daead) -> Self {
        Primitive::Daead(value)
    }
}

impl From<crate::Mac> for Primitive {
    fn from(value: crate::Mac) -> Self {
        Primitive::Mac(value)
    }
}

impl From<crate::Signer> for Primitive {
    fn from(value: crate::Signer) -> Self {
        Primitive::Signature(value)
    }
}

impl From<&crate::Aead> for Primitive {
    fn from(value: &crate::Aead) -> Self {
        Primitive::Aead(value.clone())
    }
}

impl From<&crate::Daead> for Primitive {
    fn from(value: &crate::Daead) -> Self {
        Primitive::Daead(value.clone())
    }
}

impl From<&crate::Mac> for Primitive {
    fn from(value: &crate::Mac) -> Self {
        Primitive::Mac(value.clone())
    }
}

impl From<&crate::Signer> for Primitive {
    fn from(value: &crate::Signer) -> Self {
        Primitive::Signature(value.clone())
    }
}

#[cfg(test)]
mod tests {
    use crate::envelope::InMemory;

    use super::*;

    #[cfg(feature = "mac")]
    #[cfg(feature = "std")]
    #[tokio::test]
    async fn test_in_mem_seal_open_mac() {
        let mac = crate::mac::Mac::new(crate::mac::Algorithm::Sha256, None);
        let primary_key = mac.primary_key();
        // in a real application, you would use a real key management service.
        // InMemory is only suitable for testing.
        let in_mem = InMemory::default();
        let data = crate::Mac::seal(&mac, Aad::empty(), &in_mem).await.unwrap();
        let mac = crate::Mac::open(Aad::empty(), data, &in_mem).await.unwrap();
        assert_eq!(mac.primary_key(), primary_key);
    }
}
