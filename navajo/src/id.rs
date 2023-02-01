use ring::rand::{SecureRandom, SystemRandom};
use std::collections::HashSet;

use crate::{rand, UnspecifiedError};

pub(crate) fn gen_id() -> Result<u32, UnspecifiedError> {
    let mut data = [0; 4];
    rand::fill(&mut data)?;
    let mut value: u32 = u32::from_be_bytes(data);
    while value < 100_000_000 {
        rand::fill(&mut data)?;
        value = u32::from_be_bytes(data);
    }
    Ok(value)
}

pub(crate) fn gen_unique_id(lookup: &HashSet<u32>) -> Result<u32, UnspecifiedError> {
    let mut id = gen_id()?;
    loop {
        if !lookup.contains(&id) {
            return Ok(id);
        }
        id = gen_id()?;
    }
}
