#[cfg(feature = "ring")]
use ring::rand::{SecureRandom as _, SystemRandom};

use random::{rngs::OsRng, CryptoRng, RngCore};

pub(crate) fn fill(dst: &mut [u8]) {
    Random::fill(dst)
}

/// A random number generator that uses [*ring*'s `SystemRandom`](https://docs.rs/ring/0.16.20/ring/rand/struct.SystemRandom.html) if the `"ring"`
/// feature is enabled, otherwise it uses [rand's `OsRng`](https://docs.rs/rand/0.8/rand/rngs/struct.OsRng.html).
pub struct Random;

impl CryptoRng for Random {}

impl Random {
    pub fn new() -> Self {
        Self
    }

    pub fn fill(dst: &mut [u8]) {
        #[cfg(feature = "ring")]
        SystemRandom::new().fill(dst).unwrap_or_else(|_| {
            OsRng.fill_bytes(dst);
        });
        OsRng.fill_bytes(dst);
    }
}

#[cfg(feature = "ring")]
impl RngCore for Random {
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
        OsRng.fill_bytes(dest);
        SystemRandom::new().fill(dest).ok().map_or((), |_| ())
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), random::Error> {
        SystemRandom::new()
            .fill(dest)
            .or_else(|_| OsRng.try_fill_bytes(dest))
    }
}

#[cfg(not(feature = "ring"))]
impl RngCore for Random {
    fn next_u32(&mut self) -> u32 {
        OsRng.next_u32()
    }

    fn next_u64(&mut self) -> u64 {
        OsRng.next_u64()
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        OsRng.fill_bytes(dest)
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), random::Error> {
        OsRng.try_fill_bytes(dest)
    }
}
