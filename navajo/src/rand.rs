use inherent::inherent;
use rand_core::{CryptoRng, RngCore};

use crate::{error::RandomError, sealed::Sealed};

/// Random number generator
pub trait Random: Clone + Sealed {
    fn fill(&self, dst: &mut [u8]) -> Result<(), RandomError>;
    fn u8(&self) -> Result<u8, RandomError>;
    fn u16(&self) -> Result<u16, RandomError>;
    fn u32(&self) -> Result<u32, RandomError>;
    fn u64(&self) -> Result<u64, RandomError>;
    fn u128(&self) -> Result<u128, RandomError>;
    fn usize(&self) -> Result<usize, RandomError>;
}
#[cfg(feature = "ring")]

/// A random number generator that uses [*ring*'s `SystemRandom`](`ring::rand::SystemRandom`) if the `"ring"`
/// feature is enabled, otherwise it uses [rand's `OsRng`](`random::rngs::OsRng`).
///
/// If *ring* fails, it will make a fallback attempt with [`rand::rngs::OsRng`](`random::rngs::OsRng`).
#[derive(Clone, Copy, Default)]
pub struct SystemRandom;
impl Sealed for SystemRandom {}
impl CryptoRng for SystemRandom {}

fn fill(dst: &mut [u8]) -> Result<(), RandomError> {
    #[cfg(feature = "ring")]
    {
        if ring::rand::SecureRandom::fill(&ring::rand::SystemRandom::new(), dst).is_ok() {
            return Ok(());
        }
    }
    rand_core::OsRng.try_fill_bytes(dst)?;
    Ok(())
}

impl SystemRandom {
    pub fn new() -> Self {
        Self
    }
}

#[inherent]
impl Random for SystemRandom {
    pub fn fill(&self, dst: &mut [u8]) -> Result<(), RandomError> {
        fill(dst)
    }

    pub fn u8(&self) -> Result<u8, RandomError> {
        let mut dst = [0; 1];
        fill(&mut dst)?;
        Ok(dst[0])
    }

    pub fn u16(&self) -> Result<u16, RandomError> {
        let mut dst = [0; 2];
        fill(&mut dst)?;
        Ok(u16::from_ne_bytes(dst))
    }

    pub fn u32(&self) -> Result<u32, RandomError> {
        let mut dst = [0; 4];
        fill(&mut dst)?;
        Ok(u32::from_ne_bytes(dst))
    }

    pub fn u64(&self) -> Result<u64, RandomError> {
        let mut dst = [0; 8];
        fill(&mut dst)?;
        Ok(u64::from_ne_bytes(dst))
    }

    pub fn u128(&self) -> Result<u128, RandomError> {
        let mut dst = [0; 16];
        fill(&mut dst)?;
        Ok(u128::from_ne_bytes(dst))
    }

    pub fn usize(&self) -> Result<usize, RandomError> {
        #[cfg(target_pointer_width = "64")]
        {
            let mut dst = [0; 8];
            fill(&mut dst)?;
            Ok(usize::from_ne_bytes(dst))
        }
        #[cfg(target_pointer_width = "32")]
        {
            let mut dst = [0; 4];
            fill(&mut dst)?;
            Ok(usize::from_ne_bytes(dst))
        }
        #[cfg(all(not(target_pointer_width = "64"), not(target_pointer_width = "32")))]
        {
            compile_error!("Unsupported target_pointer_width")
        }
    }
}

impl RngCore for SystemRandom {
    fn next_u32(&mut self) -> u32 {
        match self.u32() {
            Ok(v) => v,
            Err(e) => {
                panic!("{}", e)
            }
        }
    }
    fn next_u64(&mut self) -> u64 {
        match self.u64() {
            Ok(v) => v,
            Err(e) => {
                panic!("{}", e)
            }
        }
    }
    fn fill_bytes(&mut self, dst: &mut [u8]) {
        match self.fill(dst) {
            Ok(v) => v,
            Err(e) => {
                panic!("{}", e)
            }
        }
    }
    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core::Error> {
        self.fill(dest)?;
        Ok(())
    }
}

// ===================================================
// ====================== MOCK =======================
// ===================================================

// mockall does not support no_std

#[cfg(all(test, feature = "std"))]
mockall::mock! {
    pub RandomInner {}
    impl Random for RandomInner {
        fn fill(&self, dst: &mut [u8]) -> Result<(), RandomError>;
        fn u8(&self) -> Result<u8, RandomError>;
        fn u16(&self) -> Result<u16, RandomError>;
        fn u32(&self) -> Result<u32, RandomError>;
        fn u64(&self) -> Result<u64, RandomError>;
        fn u128(&self) -> Result<u128, RandomError>;
        fn usize(&self) -> Result<usize, RandomError>;
    }

}
#[cfg(all(test, feature = "std"))]
impl Sealed for MockRandomInner {}

#[cfg(all(test, feature = "std"))]
impl Clone for MockRandomInner {
    fn clone(&self) -> Self {
        panic!("MockRandomInner cannot be cloned; clone must be called on MockRandom")
    }
}

#[cfg(all(test, feature = "std"))]
#[derive(Clone)]
pub struct MockRandom {
    inner: std::sync::Arc<std::sync::Mutex<MockRandomInner>>,
}
#[cfg(all(test, feature = "std"))]
impl Sealed for MockRandom {}
#[cfg(all(test, feature = "std"))]
impl CryptoRng for MockRandom {}

#[cfg(all(test, feature = "std"))]
impl MockRandom {
    pub fn new() -> Self {
        Self {
            inner: std::sync::Arc::new(std::sync::Mutex::new(MockRandomInner::new())),
        }
    }
    pub fn lock(&self) -> std::sync::MutexGuard<'_, MockRandomInner> {
        self.inner.lock().unwrap()
    }
}

#[cfg(all(test, feature = "std"))]
impl Default for MockRandom {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(all(test, feature = "std"))]
impl RngCore for MockRandom {
    fn next_u32(&mut self) -> u32 {
        self.lock().u32().unwrap()
    }
    fn next_u64(&mut self) -> u64 {
        self.lock().u64().unwrap()
    }
    fn fill_bytes(&mut self, dst: &mut [u8]) {
        self.lock().fill(dst).unwrap()
    }
    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core::Error> {
        self.lock().fill(dest).map_err(|err| err.0)
    }
}
