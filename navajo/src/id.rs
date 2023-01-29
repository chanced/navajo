use ring::rand::{SecureRandom, SystemRandom};
use std::collections::HashSet;

pub(crate) fn gen_id() -> u32 {
    let rng = SystemRandom::new();
    let mut data = [0; 4];
    let mut value: u32 = 0;
    while value < 1000000000 {
        rng.fill(&mut data).expect("failed to generate random u32");
        value = u32::from_be_bytes(data);
    }
    value
}

pub(crate) fn gen_unique_id(lookup: &HashSet<u32>) -> u32 {
    let mut id = gen_id();
    loop {
        if !lookup.contains(&id) {
            return id;
        }
        id = gen_id();
    }
}
