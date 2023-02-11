use core::fmt::{self};

use serde::{Deserialize, Serialize};

const FOUR_KB: usize = 4096;
const SIXTY_FOUR_KB: usize = 65536;
const ONE_MB: usize = 1048576;
/// Defines the size of the block segments used during STREAM encryption /
/// decription.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(into = "usize", try_from = "usize")]
#[repr(usize)]
pub enum Segment {
    FourKB = FOUR_KB,
    SixtyFourKB = SIXTY_FOUR_KB,
    OneMB = ONE_MB,
}

impl Segment {
    pub(super) fn to_usize(self) -> usize {
        self as usize
    }
}

impl fmt::Display for Segment {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Segment::FourKB => write!(f, "4 KB"),
            Segment::SixtyFourKB => write!(f, "64 KB"),
            Segment::OneMB => write!(f, "1 MB"),
        }
    }
}
impl From<Segment> for usize {
    fn from(seg: Segment) -> Self {
        seg as usize
    }
}

impl TryFrom<usize> for Segment {
    type Error = &'static str;
    fn try_from(value: usize) -> Result<Self, Self::Error> {
        match value {
            FOUR_KB => Ok(Segment::FourKB),
            SIXTY_FOUR_KB => Ok(Segment::SixtyFourKB),
            ONE_MB => Ok(Segment::OneMB),
            _ => Err("Invalid segment size"),
        }
    }
}

impl PartialEq<Segment> for usize {
    fn eq(&self, other: &Segment) -> bool {
        match other {
            Segment::FourKB => *self == FOUR_KB,
            Segment::SixtyFourKB => *self == SIXTY_FOUR_KB,
            Segment::OneMB => *self == ONE_MB,
        }
    }
}

impl PartialEq<usize> for Segment {
    fn eq(&self, other: &usize) -> bool {
        *self == *other
    }
}
