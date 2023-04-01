use crate::error::Error;

pub trait Validate {
    type Error: core::fmt::Display + core::fmt::Debug;
    fn validate(&self) -> Result<(), Self::Error>;
}
