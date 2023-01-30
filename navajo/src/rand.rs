use ring::rand::SecureRandom;

pub(crate) fn fill(dst: &mut [u8]) -> Result<(), crate::UnspecifiedError> {
    let rng = ring::rand::SystemRandom::new();
    rng.fill(dst).map_err(|_| crate::UnspecifiedError)
}
