use core::fmt;

const FOUR_KB: u32 = 4096;
const ONE_MB: u32 = 1048576;

/// Defines the size of the block segments used during STREAM encryption /
/// decription.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Segment {
    FourKB,
    OneMB,
}
impl Segment {
    pub(super) fn to_usize(self) -> usize {
        match self {
            Segment::FourKB => FOUR_KB as usize,
            Segment::OneMB => ONE_MB as usize,
        }
    }
}

impl fmt::Display for Segment {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Segment::FourKB => write!(f, "4KB"),
            Segment::OneMB => write!(f, "1MB"),
        }
    }
}
impl From<Segment> for usize {
    fn from(seg: Segment) -> Self {
        match seg {
            Segment::FourKB => FOUR_KB as usize,
            Segment::OneMB => ONE_MB as usize,
        }
    }
}

impl PartialEq<Segment> for usize {
    fn eq(&self, other: &Segment) -> bool {
        match other {
            Segment::FourKB => *self == FOUR_KB as usize,
            Segment::OneMB => *self == ONE_MB as usize,
        }
    }
}

impl PartialEq<usize> for Segment {
    fn eq(&self, other: &usize) -> bool {
        match self {
            Segment::FourKB => *other == FOUR_KB as usize,
            Segment::OneMB => *other == ONE_MB as usize,
        }
    }
}
