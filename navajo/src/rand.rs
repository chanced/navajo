#[cfg(feature = "ring")]
use ring_compat::ring::rand::{SecureRandom as _, SystemRandom};

use random::{rngs::OsRng, CryptoRng, RngCore};

pub(crate) fn fill(dst: &mut [u8]) {
    SecureRandom::new().fill_bytes(dst)
}
#[cfg(feature = "ring")]
pub struct SecureRandom;
impl CryptoRng for SecureRandom {}
impl SecureRandom {
    pub fn new() -> Self {
        Self
    }
}
#[cfg(feature = "ring")]
impl RngCore for SecureRandom {
    fn next_u32(&mut self) -> u32 {
        let mut data = [0; 4];
        SystemRandom::new()
            .fill(&mut data)
            .ok()
            .map_or(OsRng.next_u32(), |_| u32::from_be_bytes(data))
    }

    fn next_u64(&mut self) -> u64 {
        let mut data = [0; 8];
        SystemRandom::new()
            .fill(&mut data)
            .ok()
            .map_or(OsRng.next_u64(), |_| u64::from_be_bytes(data))
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        SystemRandom::new()
            .fill(dest)
            .ok()
            .map_or(OsRng.fill_bytes(dest), |_| ())
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), random::Error> {
        SystemRandom::new()
            .fill(dest)
            .or_else(|_| OsRng.try_fill_bytes(dest))
    }
}

#[cfg(not(feature = "ring"))]
impl RngCore for SecureRandom {
    fn next_u32(&mut self) -> u32 {
        OsRng.next_u32()
    }

    fn next_u64(&mut self) -> u64 {
        OsRng.next_u64()
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        OsRng.fill_bytes(dest)
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand::Error> {
        OsRng.try_fill_bytes(dest)
    }
}
