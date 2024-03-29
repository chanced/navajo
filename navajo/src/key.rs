#[cfg(not(feature = "std"))]
use alloc::sync::Arc;
use serde::{Deserialize, Serialize};

use zeroize::ZeroizeOnDrop;

use crate::{error::DisableKeyError, primitive::Kind, Metadata, Origin, Status};

pub(crate) trait KeyMaterial:
    Send + Sync + ZeroizeOnDrop + Clone + 'static + PartialEq + Eq
{
    type Algorithm: PartialEq + Eq;
    fn algorithm(&self) -> Self::Algorithm;
    fn kind() -> Kind;
}

#[derive(Debug, Clone, Serialize, Deserialize, ZeroizeOnDrop)]
pub(crate) struct Key<M>
where
    M: KeyMaterial,
{
    id: u32,
    #[zeroize(skip)]
    status: Status,
    #[zeroize(skip)]
    origin: Origin,
    #[serde(flatten)]
    material: M,
    #[zeroize(skip)]
    #[serde(skip_serializing_if = "Option::is_none")]
    metadata: Option<Metadata>,
}

impl<M> Key<M>
where
    M: KeyMaterial,
{
    pub(crate) fn new(
        id: u32,
        status: Status,
        origin: Origin,
        material: M,
        metadata: Option<Metadata>,
    ) -> Self {
        Self {
            id,
            status,
            origin,
            material,
            metadata,
        }
    }
    pub(crate) fn id(&self) -> u32 {
        self.id
    }

    pub(crate) fn metadata(&self) -> Option<&Metadata> {
        self.metadata.as_ref()
    }
    pub(crate) fn take_metadata(&mut self) -> Option<Metadata> {
        self.metadata.take()
    }

    pub(crate) fn disable(&mut self) -> Result<&Self, DisableKeyError> {
        if self.status.is_primary() {
            Err(DisableKeyError::IsPrimaryKey(self.id))
        } else {
            self.status = Status::Disabled;
            Ok(self)
        }
    }

    pub(crate) fn promote(&mut self) -> &Self {
        self.status = Status::Primary;
        self
    }

    pub(crate) fn demote(&mut self) -> &Self {
        self.status = Status::Enabled;
        self
    }
    pub(crate) fn enable(&mut self) -> &Self {
        self.status = Status::Enabled;
        self
    }

    pub fn key_bytes(&self) -> [u8; 4] {
        self.id.to_be_bytes()
    }

    pub(crate) fn update_meta(&mut self, meta: Option<Metadata>) -> &Key<M> {
        self.metadata = meta;
        self
    }

    pub(crate) fn algorithm(&self) -> M::Algorithm
    where
        M: KeyMaterial,
    {
        self.material.algorithm()
    }
    pub fn status(&self) -> Status {
        self.status
    }
    pub(crate) fn material(&self) -> &M {
        &self.material
    }
    pub(crate) fn origin(&self) -> Origin {
        self.origin
    }
    pub(crate) fn is_primary(&self) -> bool {
        self.status.is_primary()
    }
    // pub(crate) fn is_secondary(&self) -> bool {
    //     self.status.is_secondary()
    // }
    // pub(crate) fn is_disabled(&self) -> bool {
    //     self.status.is_disabled()
    // }
    // pub(crate) fn can_delete(&self) -> bool {
    //     !self.status.is_primary()
    // }
}
impl<M> PartialEq for Key<M>
where
    M: KeyMaterial,
{
    fn eq(&self, other: &Self) -> bool {
        self.id == other.id && self.material == other.material
    }
}
impl<M> From<&Key<M>> for u32
where
    M: KeyMaterial,
{
    fn from(value: &Key<M>) -> Self {
        value.id
    }
}
impl<M> From<Key<M>> for u32
where
    M: KeyMaterial,
{
    fn from(value: Key<M>) -> Self {
        value.id
    }
}

#[cfg(test)]
pub(crate) mod test {
    #[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
    pub(crate) enum Algorithm {
        Pancakes,
        Waffles,
        FrenchToast,
        Cereal,
    }
    #[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, ZeroizeOnDrop)]
    pub(crate) struct Material {
        #[zeroize(skip)]
        algorithm: Algorithm,
        value: [u8; 32],
    }
    impl Material {
        pub(crate) fn new(algorithm: Algorithm) -> Self {
            let mut value = [0u8; 32];
            crate::SystemRng.fill(&mut value).unwrap();
            Self { algorithm, value }
        }
    }

    impl super::KeyMaterial for Material {
        type Algorithm = Algorithm;
        fn algorithm(&self) -> Self::Algorithm {
            self.algorithm
        }
        fn kind() -> crate::primitive::Kind {
            crate::primitive::Kind::Aead
        }
    }

    use super::*;
    #[test]
    fn test_serialize() {
        let key = Key::new(
            1,
            Status::Primary,
            Origin::Navajo,
            Material::new(Algorithm::Pancakes),
            None,
        );
        let ser = serde_json::to_string(&key).unwrap();
        let de = serde_json::from_str(&ser).unwrap();
        assert_eq!(key, de);
    }
    #[test]
    fn test_status() {
        let mut key = Key::new(
            1,
            Status::Primary,
            Origin::Navajo,
            Material::new(Algorithm::Pancakes),
            None,
        );

        key.demote();
        assert_eq!(key.status(), Status::Enabled);

        key.promote();
        assert_eq!(key.status(), Status::Primary);
        assert!(key.disable().is_err());
        key.demote();
        assert!(key.disable().is_ok());
        key.promote();
        assert!(!key.status.is_secondary());
        key.demote();
        assert!(key.status.is_secondary());
    }
    // #[test]
    // fn test_meta() {
    //     let mut key = Key::new(
    //         1,
    //         Status::Primary,
    //         Origin::Navajo,
    //         Material::new(Algorithm::Pancakes),
    //         Some(Arc::new("(╯°□°）╯︵ ┻━┻".into())),
    //     );
    //     assert_eq!(
    //         key.metadata.as_deref(),
    //         Some("(╯°□°）╯︵ ┻━┻".into()).as_ref()
    //     );
    //     key.update_meta(Some("┬─┬ノ( º _ ºノ)".into()));
    //     assert_eq!(
    //         key.metadata.as_deref(),
    //         Some("┬─┬ノ( º _ ºノ)".into()).as_ref()
    //     );
    // }
}
