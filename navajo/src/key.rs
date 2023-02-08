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
    material: Arc<M>,
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
            material: Arc::new(material),
            meta: meta.map(Arc::new),
        }
    }
    pub(crate) fn id(&self) -> u32 {
        self.id
    }
    pub(crate) fn meta(&self) -> Option<&Value> {
        self.meta.as_ref().map(Arc::as_ref)
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
    pub(crate) fn update_meta(&mut self, meta: Option<serde_json::Value>) {
        self.meta = meta.map(Arc::new);
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
