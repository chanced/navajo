///! Constant-time operations
///
///
use crate::error::UnspecifiedError;
/// Compares `a` and `b` at constant-time with repect to each other, unless the
/// lengths are not equal.
///
/// ## Errors
/// Returns [`Err(UnspecifiedError)`](crate::error::UnspecifiedError) if `a` and `b` are not equal.
pub fn verify_slices_are_equal(a: &[u8], b: &[u8]) -> Result<(), UnspecifiedError> {
    if a.len() != b.len() {
        return Err(UnspecifiedError);
    }
    #[cfg(feature = "ring")]
    {
        ring::constant_time::verify_slices_are_equal(a, b).map_err(|_| UnspecifiedError)
    }
    #[cfg(not(feature = "ring"))]
    {
        use subtle::ConstantTimeEq;
        if a.ct_eq(b).unwrap_u8() == 1 {
            Ok(())
        } else {
            Err(UnspecifiedError)
        }
    }
}
