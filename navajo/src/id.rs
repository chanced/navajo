use std::collections::HashSet;

use crate::error::UnspecifiedError;
use crate::rand;

pub(crate) fn gen_id() -> u32 {
    let mut data = [0; 4];
    rand::fill(&mut data);
    let mut value: u32 = u32::from_be_bytes(data);
    while value < 100_000_000 {
        rand::fill(&mut data);
        value = u32::from_be_bytes(data);
    }
    value
}

pub(crate) fn gen_unique_id(lookup: &HashSet<u32>) -> u32 {
    let mut id = gen_id();
    while lookup.contains(&id){
        id = gen_id();
    }
    id
}
