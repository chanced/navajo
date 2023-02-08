use serde::{Deserialize, Serialize};

use crate::{mac::Mac, Kms, KmsSync};

pub enum Primitive {
    Aead(),
    Daead,
    Mac(Mac),
}
impl From<Primitive> for ProtectedPrimitive {
    fn from(p: Primitive) -> Self {
        match p {
            Primitive::Aead() => Self::Aead(),
            Primitive::Daead => Self::Daead,
            Primitive::Mac(m) => Self::Mac(m),
        }
    }
}

enum ProtectedPrimitive {
    Aead(),
    Daead,
    Mac(Mac),
}

// impl AsPrimitive for Primitive {
//     fn as_primitive(&self) -> Primitive {
//         self.clone()
//     }
// }
// impl Primitive {}

// pub async fn seal<E, P>(
//     envelope: E,
//     primitive: P,
//     additional_data: &[u8],
// ) -> Result<(), E::EncryptError>
// where
//     E: Envelope,
//     P: AsPrimitive,
// {
//     todo!()
// }
// pub async fn open<E, P>(
//     envelope: E,
//     primitive: P,
//     additional_data: &[u8],
// ) -> Result<(), E::DecryptError>
// where
//     E: Envelope,
//     P: AsPrimitive,
// {
//     todo!()
// }
// pub fn seal_sync<E, P>(
//     envelope: E,
//     primitive: P,
//     additional_data: &[u8],
// ) -> Result<(), E::EncryptError>
// where
//     E: EnvelopeSync,
//     P: AsPrimitive,
// {
//     todo!()
// }
// pub fn open_sync<E, P>(
//     envelope: E,
//     primitive: P,
//     additional_data: &[u8],
// ) -> Result<(), E::DecryptError>
// where
//     E: Envelope,
//     P: AsPrimitive,
// {
//     todo!()
// }

// pub trait AsPrimitive {
//     fn as_primitive(&self) -> Primitive;
// }

// pub trait Seal {
//     type EncryptError;
//     fn seal(&self, additional_data: &[u8]) -> Result<(), Self::EncryptError>;
// }
