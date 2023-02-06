use crate::error::UnspecifiedError;

cfg_if::cfg_if! {
    if #[cfg(feature = "ring")] {
        pub fn verify_slices_are_equal(a: &[u8], b: &[u8]) -> Result<(), UnspecifiedError> {
            ring_compat::ring::constant_time::verify_slices_are_equal(a, b).map_err(|_| UnspecifiedError)
        }
    } else {
        use subtle::ConstantTimeEq;
        pub fn verify_slices_are_equal(a: &[u8], b: &[u8]) -> Result<(), UnspecifiedError> {
            if a.ct_eq(b).unwrap_u8() == 1 {
                Ok(())
            } else {
                Err(UnspecifiedError)
            }
        }
    }
}
