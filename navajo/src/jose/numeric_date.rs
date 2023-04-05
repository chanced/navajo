use core::{
    num::TryFromIntError,
    ops::{Add, Sub},
};
use std::time::UNIX_EPOCH;

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(transparent)]
pub struct NumericDate(pub i64);

impl NumericDate {
    #[cfg(feature = "chrono")]
    pub fn from_chrono_date_time(dt: chrono::DateTime<chrono::Utc>) -> Self {
        Self(dt.timestamp())
    }

    #[cfg(feature = "chrono")]
    pub fn from_chrono_naive_date_time(ndt: chrono::NaiveDateTime) -> Self {
        Self(ndt.timestamp())
    }
    #[cfg(feature = "time")]
    pub fn from_primitive_date_time(pdt: time::PrimitiveDateTime) -> Self {
        Self(pdt.assume_utc().unix_timestamp())
    }
}

#[cfg(feature = "std")]
impl NumericDate {
    pub fn now() -> Self {
        Self(UNIX_EPOCH.elapsed().unwrap().as_secs() as i64)
    }
}

#[cfg(feature = "time")]
impl From<time::PrimitiveDateTime> for NumericDate {
    fn from(pdt: time::PrimitiveDateTime) -> Self {
        Self::from_primitive_date_time(pdt)
    }
}

#[cfg(feature = "chrono")]
impl From<chrono::NaiveDateTime> for NumericDate {
    fn from(dt: chrono::NaiveDateTime) -> Self {
        Self::from_chrono_naive_date_time(dt)
    }
}

#[cfg(feature = "chrono")]
impl From<chrono::DateTime<chrono::Utc>> for NumericDate {
    fn from(dt: chrono::DateTime<chrono::Utc>) -> Self {
        Self::from_chrono_date_time(dt)
    }
}

#[cfg(feature = "chrono")]
impl Add<chrono::Duration> for NumericDate {
    type Output = Self;
    fn add(self, rhs: chrono::Duration) -> Self::Output {
        Self(self.0 + rhs.num_seconds())
    }
}

#[cfg(feature = "time")]
impl Add<time::Duration> for NumericDate {
    type Output = Self;
    fn add(self, rhs: time::Duration) -> Self::Output {
        Self(self.0 + rhs.whole_seconds())
    }
}

#[cfg(feature = "chrono")]
impl Sub<chrono::Duration> for NumericDate {
    type Output = Self;
    fn sub(self, rhs: chrono::Duration) -> Self::Output {
        Self(self.0 - rhs.num_seconds())
    }
}

#[cfg(feature = "time")]
impl Sub<time::Duration> for NumericDate {
    type Output = Self;
    fn sub(self, rhs: time::Duration) -> Self::Output {
        Self(self.0 - rhs.whole_seconds())
    }
}

impl From<i64> for NumericDate {
    fn from(i: i64) -> Self {
        Self(i)
    }
}
impl TryFrom<u64> for NumericDate {
    type Error = TryFromIntError;
    fn try_from(u: u64) -> Result<Self, Self::Error> {
        Ok(Self(u64::try_from(i64::try_from(u)?)? as i64))
    }
}

impl Add<core::time::Duration> for NumericDate {
    type Output = Self;
    fn add(self, rhs: core::time::Duration) -> Self::Output {
        // TODO: not a fan of this but at the same time, if the duration exceeds the
        // range of i64, something has likely gone incredibly wrong on the caller's end
        // that needs to be addressed.
        match i64::try_from(rhs.as_secs()) {
            Ok(i) => Self(self.0 + i),
            Err(err) => panic!("duration too large to convert to i64: {err}"),
        }
    }
}
impl Sub<core::time::Duration> for NumericDate {
    type Output = Self;
    fn sub(self, rhs: core::time::Duration) -> Self::Output {
        // TODO: not a fan of this but at the same time, if the duration exceeds the
        // range of i64, something has likely gone incredibly wrong on the caller's end
        // that needs to be addressed.

        match i64::try_from(rhs.as_secs()) {
            Ok(i) => Self(self.0 - i),
            Err(err) => panic!("duration too large to convert to i64: {err}"),
        }
    }
}

impl PartialEq for NumericDate {
    fn eq(&self, other: &Self) -> bool {
        self.0 == other.0
    }
}

impl Eq for NumericDate {}
impl PartialEq<&Self> for NumericDate {
    fn eq(&self, other: &&Self) -> bool {
        self.0 == other.0
    }
}

impl PartialOrd for NumericDate {
    fn partial_cmp(&self, other: &Self) -> Option<core::cmp::Ordering> {
        self.0.partial_cmp(&other.0)
    }
}

impl PartialOrd<&Self> for NumericDate {
    fn partial_cmp(&self, other: &&Self) -> Option<core::cmp::Ordering> {
        self.0.partial_cmp(&other.0)
    }
}

impl Ord for NumericDate {
    fn cmp(&self, other: &Self) -> core::cmp::Ordering {
        self.0.cmp(&other.0)
    }
}

impl Sub<i64> for NumericDate {
    type Output = Self;
    fn sub(self, rhs: i64) -> Self::Output {
        Self(self.0 - rhs)
    }
}
impl Sub<u64> for NumericDate {
    type Output = Self;
    fn sub(self, rhs: u64) -> Self::Output {
        Self(self.0 - rhs as i64)
    }
}
impl Sub<i32> for NumericDate {
    type Output = Self;
    fn sub(self, rhs: i32) -> Self::Output {
        Self(self.0 - rhs as i64)
    }
}
impl Sub<usize> for NumericDate {
    type Output = Self;
    fn sub(self, rhs: usize) -> Self::Output {
        Self(self.0 - rhs as i64)
    }
}
impl Sub<u32> for NumericDate {
    type Output = Self;
    fn sub(self, rhs: u32) -> Self::Output {
        Self(self.0 - rhs as i64)
    }
}
impl Sub<i16> for NumericDate {
    type Output = Self;
    fn sub(self, rhs: i16) -> Self::Output {
        Self(self.0 - rhs as i64)
    }
}
impl Sub<u16> for NumericDate {
    type Output = Self;
    fn sub(self, rhs: u16) -> Self::Output {
        Self(self.0 - rhs as i64)
    }
}
impl Sub<i8> for NumericDate {
    type Output = Self;
    fn sub(self, rhs: i8) -> Self::Output {
        Self(self.0 - rhs as i64)
    }
}
impl Add<i64> for NumericDate {
    type Output = Self;
    fn add(self, rhs: i64) -> Self::Output {
        Self(self.0 + rhs)
    }
}
impl Sub<u8> for NumericDate {
    type Output = Self;
    fn sub(self, rhs: u8) -> Self::Output {
        Self(self.0 - rhs as i64)
    }
}
impl Add<u64> for NumericDate {
    type Output = Self;
    fn add(self, rhs: u64) -> Self::Output {
        Self(self.0 + rhs as i64)
    }
}
impl Add<i32> for NumericDate {
    type Output = Self;
    fn add(self, rhs: i32) -> Self::Output {
        Self(self.0 + rhs as i64)
    }
}
impl Add<usize> for NumericDate {
    type Output = Self;
    fn add(self, rhs: usize) -> Self::Output {
        Self(self.0 + rhs as i64)
    }
}
impl Add<u32> for NumericDate {
    type Output = Self;
    fn add(self, rhs: u32) -> Self::Output {
        Self(self.0 + rhs as i64)
    }
}
impl Add<i16> for NumericDate {
    type Output = Self;
    fn add(self, rhs: i16) -> Self::Output {
        Self(self.0 + rhs as i64)
    }
}
impl Add<u16> for NumericDate {
    type Output = Self;
    fn add(self, rhs: u16) -> Self::Output {
        Self(self.0 + rhs as i64)
    }
}
impl Add<i8> for NumericDate {
    type Output = Self;
    fn add(self, rhs: i8) -> Self::Output {
        Self(self.0 + rhs as i64)
    }
}
impl Add<u8> for NumericDate {
    type Output = Self;
    fn add(self, rhs: u8) -> Self::Output {
        Self(self.0 + rhs as i64)
    }
}
