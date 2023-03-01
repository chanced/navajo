use crate::{error::InvalidLengthError, rand::Rng, NEW_ISSUE_URL};
use core::ops::Deref;

use alloc::boxed::Box;
use generic_array::GenericArray;

use typenum::{U12, U24};

use crate::error::UnspecifiedError;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum NonceOrNonceSequence {
    Nonce(Nonce),
    NonceSequence(NonceSequence),
}
impl NonceOrNonceSequence {
    pub(crate) fn bytes(&self) -> &[u8] {
        match self {
            Self::Nonce(nonce) => nonce.bytes(),
            Self::NonceSequence(nonce_sequence) => nonce_sequence.bytes(),
        }
    }
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Nonce {
    Twelve([u8; 12]),
    /// Used for XChaCha20Poly1305. Given that all others are 12 bytes, this is
    /// going to be the least common but twice the size. As such, the value gets
    /// boxed.
    TwentyFour(Box<[u8; 24]>),
}

impl Nonce {
    pub(crate) fn new<R>(rand: R, size: usize) -> Self
    where
        R: Rng,
    {
        let mut result = match size {
            12 => Self::Twelve([0u8; 12]),
            24 => Self::TwentyFour(Box::new([0u8; 24])),
            _ => unreachable!("NonceSequence must be 12 or 24 bytes\nthis is a bug!\n\nplease report it to {NEW_ISSUE_URL}"),
        };
        match result {
            Self::Twelve(ref mut seed) => {
                rand.fill(seed);
            }
            Self::TwentyFour(ref mut seed) => {
                rand.fill(seed.as_mut());
            }
        };
        result
    }
    pub(crate) fn new_from_slice(
        size: usize,
        slice: &[u8],
    ) -> Result<Self, crate::error::InvalidLengthError> {
        match size {
            12 => Ok(Self::Twelve(slice.try_into().map_err(|_| InvalidLengthError)?)),
            24 => Ok(Self::TwentyFour(Box::new(slice.try_into().map_err(|_| InvalidLengthError)?))),
            _ => unreachable!("NonceSequence must be 12 or 24 bytes\nthis is a bug!\n\nplease report it to {NEW_ISSUE_URL}"),
        }
    }
    pub(crate) fn bytes(&self) -> &[u8] {
        match self {
            Self::Twelve(nonce) => &nonce[..],
            Self::TwentyFour(nonce) => &nonce[..],
        }
    }
}
impl Deref for Nonce {
    type Target = [u8];
    fn deref(&self) -> &Self::Target {
        self.as_ref()
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
            Nonce::TwentyFour(_) => panic!("attempted to convert a 24 byte nonce to a 12 byte nonce\nthis is a bug!\n\nplease report it to "),
        }
    }
}
impl From<Nonce> for GenericArray<u8, U24> {
    fn from(nonce: Nonce) -> Self {
        match nonce {
            Nonce::TwentyFour(nonce) => GenericArray::clone_from_slice(&nonce[..]),
            Nonce::Twelve(_) => panic!("attempted to convert a 12 byte nonce to a 24 byte nonce\nthis is a bug!\n\nplease report it to {NEW_ISSUE_URL}"),
        }
    }
}

#[cfg(feature = "ring")]
impl From<Nonce> for ring::aead::Nonce {
    fn from(nonce: Nonce) -> Self {
        match nonce {
            Nonce::Twelve(nonce) => ring::aead::Nonce::assume_unique_for_key(nonce),
            Nonce::TwentyFour(_) => unreachable!("ring does not support 24 byte nonces\nthis is a bug!\n\nplease report it to {NEW_ISSUE_URL}"),
        }
    }
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum NonceSequence {
    Twelve(u32, [u8; 12]),
    TwentyFour(u32, Box<[u8; 24]>),
}

impl NonceSequence {
    pub(crate) fn new<R>(rand: R, size: usize) -> Self
    where
        R: Rng,
    {
        let mut result = match size {
            12 => Self::Twelve(0, [0u8; 12]),
            24 => Self::TwentyFour(0, Box::new([0u8; 24])),
            _ => panic!("NonceSequence must be 12 or 24 bytes\nthis is a bug!\n\nplease report it to {NEW_ISSUE_URL}"),
        };
        match result {
            Self::Twelve(_, ref mut seed) => rand.fill(&mut seed[..12 - 5]).unwrap(),
            Self::TwentyFour(_, ref mut seed) => rand.fill(&mut seed[..24 - 5]).unwrap(),
        }
        result
    }
    pub(crate) fn new_with_prefix(len: usize, seed: &[u8]) -> Result<Self, UnspecifiedError> {
        if len - 5 != seed.len() {
            return Err(UnspecifiedError);
        }

        match seed.len() {
            7 => Ok(Self::Twelve(0, {
                let mut result = [0u8; 12];
                result[..7].copy_from_slice(seed);
                result
            })),
            19 => Ok(Self::TwentyFour(
                0,
                Box::new({
                    let mut result = [0u8; 24];
                    result[..19].copy_from_slice(seed);
                    result
                }),
            )),
            _ => Err(UnspecifiedError),
        }
    }
    pub(crate) fn prefix(&self) -> &[u8] {
        match self {
            Self::Twelve(_, seed) => &seed[..12 - 5],
            Self::TwentyFour(_, seed) => &seed[..24 - 5],
        }
    }

    pub(crate) fn counter(&self) -> u32 {
        match self {
            NonceSequence::Twelve(ctr, _) => *ctr,
            NonceSequence::TwentyFour(ctr, _) => *ctr,
        }
    }

    fn seed(&self) -> &[u8] {
        match self {
            Self::Twelve(_, seed) => seed.as_ref(),
            Self::TwentyFour(_, seed) => seed.as_ref(),
        }
    }
    fn seed_mut(&mut self) -> &mut [u8] {
        match self {
            Self::Twelve(_, seed) => seed,
            Self::TwentyFour(_, seed) => seed.as_mut_slice(),
        }
    }
    fn set_counter(&mut self, value: u32) {
        let len = self.len();
        self.seed_mut()[len - 5..len - 1].copy_from_slice(&value.to_be_bytes()[..]);
        match self {
            NonceSequence::Twelve(ref mut ctr, _) => *ctr = value,
            NonceSequence::TwentyFour(ref mut ctr, _) => *ctr = value,
        }
    }
    fn increment(&mut self) {
        self.set_counter(self.counter() + 1);
    }

    pub(crate) fn len(&self) -> usize {
        match self {
            Self::Twelve { .. } => 12,
            Self::TwentyFour { .. } => 24,
        }
    }
    fn nonce(&self) -> Nonce {
        match self {
            Self::Twelve(_, seed) => Nonce::Twelve(*seed),
            Self::TwentyFour(_, seed) => Nonce::TwentyFour(seed.clone()),
        }
    }

    pub(crate) fn next(&mut self) -> Result<Nonce, crate::error::SegmentLimitExceededError> {
        if self.counter() == u32::MAX {
            return Err(crate::error::SegmentLimitExceededError);
        }
        let nonce = self.nonce();
        self.increment();
        Ok(nonce)
    }

    pub(crate) fn last(mut self) -> Result<Nonce, crate::error::SegmentLimitExceededError> {
        if self.counter() == u32::MAX {
            return Err(crate::error::SegmentLimitExceededError);
        }
        let len = self.len();
        self.seed_mut()[len - 1] = 1;
        Ok(self.nonce())
    }

    // pub(crate) fn prefix_len(&self) -> usize {
    //     match self {
    //         NonceSequence::Twelve(_, _) => 12 - 5,
    //         NonceSequence::TwentyFour(_, _) => 24 - 5,
    //     }
    // }
    // pub(crate) fn try_into_nonce(&mut self) -> Result<Nonce, UnspecifiedError> {
    //     if self.counter() > 0 {
    //         return Err(UnspecifiedError);
    //     }
    //     Ok(match self {
    //         NonceSequence::Twelve(_, nonce) => {
    //             crate::rand::fill(&mut nonce[12 - 5..]);
    //             Nonce::Twelve(*nonce)
    //         }
    //         NonceSequence::TwentyFour(_, nonce) => {
    //             crate::rand::fill(&mut nonce[24 - 5..]);
    //             Nonce::TwentyFour(nonce.to_owned())
    //         }
    //     })
    // }

    pub(crate) fn bytes(&self) -> &[u8] {
        self.seed()
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

    use crate::SystemRng;

    use super::*;

    #[test]
    fn test_nonce_sequence_new() {
        let rand = SystemRng::new();

        let mut seq = NonceSequence::new(rand, 12);

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
        assert_eq!(last.unwrap().as_ref()[7..], vec![0, 0, 0, 5, 1]);

        let mut bounds_check = NonceSequence::new(rand, 12);
        bounds_check.set_counter(u32::MAX);
        assert!(bounds_check.next().is_err());

        let mut seq = NonceSequence::new(rand, 24);
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
        assert_eq!(last.unwrap().as_ref()[19..], vec![0, 0, 0, 5, 1]);
        let mut bounds_check = NonceSequence::new(rand, 24);
        bounds_check.set_counter(u32::MAX);
        assert!(bounds_check.next().is_err());
    }
}
