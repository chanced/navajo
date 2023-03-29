use crate::error::Error;

pub trait Validate {
    type Context;
    type Error: core::fmt::Display + core::fmt::Debug;
    fn validate(&self, ctx: &Self::Context) -> Result<(), Self::Error>;
}
