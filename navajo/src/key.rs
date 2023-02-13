use alloc::sync::Arc;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use zeroize::ZeroizeOnDrop;

use crate::{error::DisableKeyError, KeyInfo, Origin, Status};

pub(crate) trait KeyMaterial:
    Send + Sync + ZeroizeOnDrop + Clone + 'static + PartialEq + Eq
{
    type Algorithm: PartialEq + Eq;
    fn algorithm(&self) -> Self::Algorithm;
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct Key<M>
where
    M: KeyMaterial,
{
    id: u32,
    status: Status,
    origin: Origin,
    material: M,
    meta: Option<Arc<Value>>,
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
        meta: Option<serde_json::Value>,
    ) -> Self {
        Self {
            id,
            status,
            origin,
            material,
            meta: meta.map(Arc::new),
        }
    }
    pub(crate) fn id(&self) -> u32 {
        self.id
    }
    pub(crate) fn meta(&self) -> Option<Arc<Value>> {
        self.meta.clone()
    }
    pub(crate) fn meta_as_ref(&self) -> Option<&Value> {
        self.meta.as_ref().map(Arc::as_ref)
    }

    pub(crate) fn can_delete(&self) -> bool {
        !self.status.is_primary()
    }
    pub(crate) fn disable(
        &mut self,
    ) -> Result<KeyInfo<M::Algorithm>, DisableKeyError<M::Algorithm>> {
        if self.status.is_primary() {
            Err(DisableKeyError::IsPrimaryKey(self.info()))
        } else {
            self.status = Status::Disabled;
            Ok(self.info())
        }
    }

    pub(crate) fn promote_to_primary(&mut self) -> KeyInfo<M::Algorithm> {
        self.status = Status::Primary;
        self.info()
    }

    pub(crate) fn demote(&mut self) -> KeyInfo<M::Algorithm> {
        self.status = Status::Secondary;
        self.info()
    }
    pub(crate) fn enable(&mut self) -> KeyInfo<M::Algorithm> {
        self.status = Status::Secondary;
        self.info()
    }
    pub(crate) fn info(&self) -> KeyInfo<M::Algorithm>
    where
        M: KeyMaterial,
    {
        KeyInfo {
            id: self.id,
            origin: self.origin,
            status: self.status,
            algorithm: self.material.algorithm(),
            meta: self.meta.clone(),
        }
    }
    pub(crate) fn update_meta(&mut self, meta: Option<serde_json::Value>) -> &Key<M> {
        self.meta = meta.map(Arc::new);
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
    pub(crate) fn is_secondary(&self) -> bool {
        self.status.is_secondary()
    }
    pub(crate) fn is_disabled(&self) -> bool {
        self.status.is_disabled()
    }
}
impl<M> PartialEq for Key<M>
where
    M: KeyMaterial,
{
    fn eq(&self, other: &Self) -> bool {
        self.id == other.id && self.material == other.material
    }
}
impl<M> From<&Key<M>> for KeyInfo<M::Algorithm>
where
    M: KeyMaterial,
{
    fn from(k: &Key<M>) -> Self {
        k.info()
    }
}
impl<M> From<Key<M>> for u32
where
    M: KeyMaterial,
{
    fn from(k: Key<M>) -> Self {
        k.id
    }
}
impl<M> From<&Key<M>> for u32
where
    M: KeyMaterial,
{
    fn from(k: &Key<M>) -> Self {
        k.id
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
        bytes: [u8; 32],
    }
    impl Material {
        pub(crate) fn new(algorithm: Algorithm) -> Self {
            let mut bytes = [0u8; 32];
            crate::rand::fill(&mut bytes);
            Self { algorithm, bytes }
        }
    }
    impl super::KeyMaterial for Material {
        type Algorithm = Algorithm;
        fn algorithm(&self) -> Self::Algorithm {
            self.algorithm
        }
    }

    use super::*;
    #[test]
    fn test_serialize() {
        let key = Key::new(
            1,
            Status::Primary,
            Origin::Generated,
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
            Origin::Generated,
            Material::new(Algorithm::Pancakes),
            None,
        );

        key.demote();
        assert_eq!(key.status(), Status::Secondary);

        key.promote_to_primary();
        assert_eq!(key.status(), Status::Primary);
        assert!(key.disable().is_err());
        key.demote();
        assert!(key.disable().is_ok());
        key.promote_to_primary();
        assert!(!key.can_delete());
        key.demote();
        assert!(key.can_delete());
    }
    #[test]
    fn test_meta() {
        let mut key = Key::new(
            1,
            Status::Primary,
            Origin::Generated,
            Material::new(Algorithm::Pancakes),
            Some("(╯°□°）╯︵ ┻━┻".into()),
        );
        assert_eq!(key.meta_as_ref(), Some("(╯°□°）╯︵ ┻━┻".into()).as_ref());
        key.update_meta(Some("┬─┬ノ( º _ ºノ)".into()));
        assert_eq!(key.meta_as_ref(), Some("┬─┬ノ( º _ ºノ)".into()).as_ref());
    }
}
