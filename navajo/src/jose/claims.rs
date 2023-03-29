use super::Header;
use crate::error::Error;
use serde::{de::DeserializeOwned, Serialize};
use serde_json::Value;

pub trait Claims: core::fmt::Debug + Serialize + DeserializeOwned {
    type Context;
    type Error: Error;
    fn validate(ctx: &Self::Context, header: &Header, value: &Value) -> Result<(), Self::Error>;
}
