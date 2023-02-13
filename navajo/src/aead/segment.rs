use core::fmt::{self};

use serde::{Deserialize, Serialize};

const FOUR_KB: usize = 4096;
const SIXTY_FOUR_KB: usize = 65536;
const ONE_MB: usize = 1048576;
const FOUR_MB: usize = 4194304;
/// Defines the size of the block segments used during STREAM encryption /
/// decription.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(into = "usize", try_from = "usize")]
#[repr(usize)]
pub enum Segment {
    FourKiloBytes = FOUR_KB,
    SixtyFourKiloBytes = SIXTY_FOUR_KB,
    OneMegaByte = ONE_MB,
    FourMegaBytes = FOUR_MB,
}

impl Segment {
    pub(super) fn to_usize(self) -> usize {
        self as usize
    }
}

impl fmt::Display for Segment {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Segment::FourKiloBytes => write!(f, "4 KB"),
            Segment::SixtyFourKiloBytes => write!(f, "64 KB"),
            Segment::OneMegaByte => write!(f, "1 MB"),
            Segment::FourMegaBytes => write!(f, "4 MB"),
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
            FOUR_KB => Ok(Segment::FourKiloBytes),
            SIXTY_FOUR_KB => Ok(Segment::SixtyFourKiloBytes),
            ONE_MB => Ok(Segment::OneMegaByte),
            FOUR_MB => Ok(Segment::FourMegaBytes),
            _ => Err("Invalid segment size"),
        }
    }
}

impl PartialEq<Segment> for usize {
    fn eq(&self, other: &Segment) -> bool {
        match other {
            Segment::FourKiloBytes => *self == FOUR_KB,
            Segment::SixtyFourKiloBytes => *self == SIXTY_FOUR_KB,
            Segment::OneMegaByte => *self == ONE_MB,
            Segment::FourMegaBytes => *self == FOUR_MB,
        }
    }
}

impl PartialEq<usize> for Segment {
    fn eq(&self, other: &usize) -> bool {
        *self == *other
    }
}
