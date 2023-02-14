use alloc::boxed::Box;
use generic_array::GenericArray;

use typenum::{U12, U24};

use crate::error::UnspecifiedError;

pub(crate) enum Nonce {
    Twelve([u8; 12]),
    /// Used for XChaCha20Poly1305. Given that all others are 12 bytes, this is
    /// going to be the least common but twice the size. As such, the value gets
    /// boxed.
    TwentyFour(Box<[u8; 24]>),
}

impl Nonce {
    pub(crate) fn new(size: usize) -> Self {
        let mut result = match size {
            12 => Self::Twelve([0u8; 12]),
            24 => Self::TwentyFour(Box::new([0u8; 24])),
            _ => unreachable!("NonceSequence must be 12 or 24 bytes\nthis is a bug!\n\nplease report it to https://github.com/chanced/navajo/issues/new"),
        };
        match result {
            Self::Twelve(ref mut seed) => {
                crate::rand::fill(seed);
            }
            Self::TwentyFour(ref mut seed) => {
                crate::rand::fill(seed.as_mut());
            }
        };
        result
    }
}

impl AsRef<[u8]> for Nonce {
    fn as_ref(&self) -> &[u8] {
        match self {
            Nonce::Twelve(nonce) => &nonce[..],
            Nonce::TwentyFour(nonce) => &nonce[..],
        }
    }
}

impl TryFrom<&[u8]> for Nonce {
    type Error = UnspecifiedError;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        match value.len() {
            12 => Ok(Self::Twelve(value.try_into().unwrap())),
            24 => Ok(Self::TwentyFour(Box::new(value.try_into().unwrap()))),
            _ => Err(UnspecifiedError),
        }
    }
}
impl From<Nonce> for GenericArray<u8, U12> {
    fn from(nonce: Nonce) -> Self {
        match nonce {
            Nonce::Twelve(nonce) => GenericArray::clone_from_slice(&nonce[..]),
            Nonce::TwentyFour(nonce) => panic!("attempted to convert a 24 byte nonce to a 12 byte nonce\nthis is a bug!\n\nplease report it to https://github.com/chanced/navajo/issues/new"),
        }
    }
}
impl From<Nonce> for GenericArray<u8, U24> {
    fn from(nonce: Nonce) -> Self {
        match nonce {
            Nonce::TwentyFour(nonce) => GenericArray::clone_from_slice(&nonce[..]),
            Nonce::Twelve(nonce) => panic!("attempted to convert a 12 byte nonce to a 24 byte nonce\nthis is a bug!\n\nplease report it to https://github.com/chanced/navajo/issues/new"),
        }
    }
}

#[cfg(feature = "ring")]
impl From<Nonce> for ring::aead::Nonce {
    fn from(nonce: Nonce) -> Self {
        match nonce {
            Nonce::Twelve(nonce) => ring::aead::Nonce::assume_unique_for_key(nonce),
            Nonce::TwentyFour(nonce) => unreachable!("ring does not support 24 byte nonces\nthis is a bug!\n\nplease report it to https://github.com/chanced/navajo/issues/new"),
        }
    }
}

pub(crate) enum NonceSequence {
    Twelve([u8; 12]),
    TwentyFour(Box<[u8; 24]>),
}

impl NonceSequence {
    pub(crate) fn new(size: usize) -> Self {
        let mut result = match size {
            12 => Self::Twelve([0u8; 12]),
            24 => Self::TwentyFour(Box::new([0u8; 24])),
            _ => panic!("NonceSequence must be 12 or 24 bytes\nthis is a bug!\n\nplease report it to https://github.com/chanced/navajo/issues/new"),
        };
        match result {
            Self::Twelve(ref mut seed) => crate::rand::fill(&mut seed[..12 - 5]),
            Self::TwentyFour(ref mut seed) => crate::rand::fill(&mut seed[..24 - 5]),
        }
        result
    }
    pub(crate) fn counter(&self) -> u32 {
        u32::from_be_bytes(
            self.seed()[self.len() - 5..self.len() - 1]
                .try_into()
                .unwrap(),
        )
    }

    fn seed(&self) -> &[u8] {
        match self {
            Self::Twelve(seed) => seed.as_ref(),
            Self::TwentyFour(seed) => seed.as_ref(),
        }
    }
    fn seed_mut(&mut self) -> &mut [u8] {
        match self {
            Self::Twelve(seed) => seed,
            Self::TwentyFour(seed) => seed.as_mut_slice(),
        }
    }
    fn set_counter(&mut self, value: u32) {
        let len = self.len();
        self.seed_mut()[len - 5..len - 1].copy_from_slice(&value.to_be_bytes()[..]);
    }
    fn increment_seed(&mut self) -> Result<(), crate::error::CounterLimitExceeded> {
        let mut counter = self.counter();
        if counter == u32::MAX {
            return Err(crate::error::CounterLimitExceeded);
        }
        counter += 1;
        self.set_counter(counter);
        Ok(())
    }

    pub(crate) fn len(&self) -> usize {
        match self {
            Self::Twelve { .. } => 12,
            Self::TwentyFour { .. } => 24,
        }
    }
    fn nonce(&self) -> Nonce {
        match self {
            Self::Twelve(seed) => Nonce::Twelve(*seed),
            Self::TwentyFour(seed) => Nonce::TwentyFour(seed.clone()),
        }
    }

    fn set_last_block_flag(mut self) -> Nonce {
        let len = self.len();
        self.seed_mut()[len - 1] = 1;
        self.nonce()
    }
    pub(crate) fn next(&mut self) -> Result<Nonce, crate::error::CounterLimitExceeded> {
        let nonce = self.nonce();
        self.increment_seed()?;
        Ok(nonce)
    }

    pub(crate) fn last(self) -> Nonce {
        self.set_last_block_flag()
    }
}

// impl TryFrom<&[u8]> for NonceSequence {
//     type Error = crate::error::UnspecifiedError;
//     fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
//         let mut seed = [0u8; N];
//         if bytes.len() != N - 5 {
//             return Err(crate::error::UnspecifiedError);
//         }
//         seed.copy_from_slice(bytes);
//         Ok(Self {
//             seed,
//             counter: 0,
//             len: N,
//         })
//     }
// }

#[cfg(test)]
mod tests {
    use alloc::vec;

    use super::*;

    #[test]
    fn test_nonce_sequence_new() {
        let mut seq = NonceSequence::new(12);
        assert_ne!(seq.seed()[..7], [0u8; 7]);
        assert_eq!(seq.seed()[7..], [0u8; 5]);

        let next = seq.next().unwrap();
        assert_eq!(next.as_ref()[..7], seq.seed()[..7]);
        assert_eq!(next.as_ref()[7..], vec![0, 0, 0, 0, 0]);

        let next = seq.next().unwrap();
        assert_eq!(next.as_ref()[..7], seq.seed()[..7]);
        assert_eq!(next.as_ref()[7..], vec![0, 0, 0, 1, 0]);

        let next = seq.next().unwrap();
        assert_eq!(next.as_ref()[7..], vec![0, 0, 0, 2, 0]);

        let next = seq.next().unwrap();
        assert_eq!(next.as_ref()[7..], vec![0, 0, 0, 3, 0]);

        let next = seq.next().unwrap();
        assert_eq!(next.as_ref()[7..], vec![0, 0, 0, 4, 0]);

        let last = seq.last();
        assert_eq!(last.as_ref()[7..], vec![0, 0, 0, 5, 1]);

        let mut bounds_check = NonceSequence::new(12);
        bounds_check.set_counter(u32::MAX);
        assert!(bounds_check.next().is_err());

        let mut seq = NonceSequence::new(24);
        assert_ne!(seq.seed()[..19], [0u8; 19]);
        assert_eq!(seq.seed()[19..], [0u8; 5]);

        let next = seq.next().unwrap();
        assert_eq!(next.as_ref()[..19], seq.seed()[..19]);
        assert_eq!(next.as_ref()[19..], vec![0, 0, 0, 0, 0]);

        let next = seq.next().unwrap();
        assert_eq!(next.as_ref()[..19], seq.seed()[..19]);
        assert_eq!(next.as_ref()[19..], vec![0, 0, 0, 1, 0]);

        let next = seq.next().unwrap();
        assert_eq!(next.as_ref()[19..], vec![0, 0, 0, 2, 0]);

        let next = seq.next().unwrap();
        assert_eq!(next.as_ref()[19..], vec![0, 0, 0, 3, 0]);

        let next = seq.next().unwrap();
        assert_eq!(next.as_ref()[19..], vec![0, 0, 0, 4, 0]);

        let last = seq.last();
        assert_eq!(last.as_ref()[19..], vec![0, 0, 0, 5, 1]);

        let mut bounds_check = NonceSequence::new(24);
        bounds_check.set_counter(u32::MAX);
        assert!(bounds_check.next().is_err());
    }
}
