use crate::error::UnspecifiedError;
#[cfg(feature = "ring")]
pub fn verify_slices_are_equal(a: &[u8], b: &[u8]) -> Result<(), UnspecifiedError> {
    match ring_compat::ring::constant_time::verify_slices_are_equal(a, b) {
        Ok(()) => Ok(()),
        Err(_) => Err(UnspecifiedError),
    }
}
