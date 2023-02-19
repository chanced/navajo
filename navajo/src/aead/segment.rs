use core::{
    fmt::{self},
    ops::{Add, Sub},
};

use serde::{Deserialize, Serialize};

pub(super) const FOUR_KB: usize = 4096;
pub(super) const SIXTY_FOUR_KB: usize = 65536;
pub(super) const ONE_MB: usize = 1048576;
pub(super) const FOUR_MB: usize = 4194304;
/// Defines the size of the block segments used during STREAM encryption /
/// decription.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(into = "usize", try_from = "usize")]
#[repr(usize)]
pub enum Segment {
    FourKilobytes = FOUR_KB,
    SixtyFourKilobytes = SIXTY_FOUR_KB,
    OneMegabyte = ONE_MB,
    FourMegabytes = FOUR_MB,
}

impl Sub for Segment {
    type Output = usize;
    fn sub(self, rhs: Self) -> Self::Output {
        self.to_usize() - rhs.to_usize()
    }
}
impl Sub<Segment> for usize {
    type Output = usize;
    fn sub(self, rhs: Segment) -> Self::Output {
        self - rhs.to_usize()
    }
}
impl Sub<usize> for Segment {
    type Output = usize;
    fn sub(self, rhs: usize) -> Self::Output {
        self.to_usize() - rhs
    }
}
impl Add<usize> for Segment {
    type Output = usize;
    fn add(self, rhs: usize) -> Self::Output {
        self.to_usize() + rhs
    }
}
impl Add<Segment> for usize {
    type Output = usize;

    fn add(self, rhs: Segment) -> Self::Output {
        self + rhs.to_usize()
    }
}

impl PartialEq<usize> for Segment {
    fn eq(&self, other: &usize) -> bool {
        self.to_usize() == *other
    }
}

impl PartialOrd<usize> for Segment {
    fn partial_cmp(&self, other: &usize) -> Option<core::cmp::Ordering> {
        self.to_usize().partial_cmp(other)
    }
}
impl PartialEq<Segment> for usize {
    fn eq(&self, other: &Segment) -> bool {
        self.eq(&other.to_usize())
    }
}

impl PartialOrd<Segment> for usize {
    fn partial_cmp(&self, other: &Segment) -> Option<core::cmp::Ordering> {
        self.partial_cmp(&other.to_usize())
    }
}

impl Segment {
    pub(super) fn to_usize(self) -> usize {
        self as usize
    }
}

impl fmt::Display for Segment {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Segment::FourKilobytes => write!(f, "4 KB"),
            Segment::SixtyFourKilobytes => write!(f, "64 KB"),
            Segment::OneMegabyte => write!(f, "1 MB"),
            Segment::FourMegabytes => write!(f, "4 MB"),
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
            FOUR_KB => Ok(Segment::FourKilobytes),
            SIXTY_FOUR_KB => Ok(Segment::SixtyFourKilobytes),
            ONE_MB => Ok(Segment::OneMegabyte),
            FOUR_MB => Ok(Segment::FourMegabytes),
            _ => Err("Invalid segment size"),
        }
    }
}
