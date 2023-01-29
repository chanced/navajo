pub trait Rand: Clone {
    fn new() -> Self;
    fn fill(&self, dest: &mut [u8]) -> Result<(), crate::error::UnspecifiedError>;
}

impl Rand for ring::rand::SystemRandom {
    fn new() -> Self {
        ring::rand::SystemRandom::new()
    }
    fn fill(&self, dest: &mut [u8]) -> Result<(), crate::error::UnspecifiedError> {
        ring::rand::SecureRandom::fill(self, dest).map_err(|e| e.into())
    }
}

pub type DefaultRandom = ring::rand::SystemRandom;
