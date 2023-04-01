use core::{num::TryFromIntError, ops::Add};
use std::time::UNIX_EPOCH;

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(transparent)]
pub struct NumericDate(pub i64);

impl NumericDate {
    #[cfg(feature = "chrono")]
    pub fn from_chrono_date_time(
        dt: chrono::DateTime<chrono::Utc>,
    ) -> Result<Self, TryFromIntError> {
        Ok(Self(dt.timestamp().try_into()?))
    }

    #[cfg(feature = "chrono")]
    pub fn from_chrono_naive_date_time(
        ndt: chrono::NaiveDateTime,
    ) -> Result<Self, TryFromIntError> {
        Ok(Self(ndt.timestamp().try_into()?))
    }
    #[cfg(feature = "time")]
    pub fn from_primitive_date_time(pdt: time::PrimitiveDateTime) -> Self {
        Self(pdt.assume_utc().unix_timestamp())
    }
}

#[cfg(feature = "chrono")]
impl TryFrom<chrono::DateTime<chrono::Utc>> for NumericDate {
    type Error = TryFromIntError;
    fn try_from(dt: chrono::DateTime<chrono::Utc>) -> Result<Self, Self::Error> {
        Self::from_chrono_date_time(dt)
    }
}

//     pub fn from_naive_date_time(ndt: NaiveDateTime) -> Self {
//         Self(DateTime::from_utc(ndt, chrono::Utc))
//     }
//     pub fn to_date_time(&self) -> DateTime<Utc> {
//         self.0
//     }
//     pub fn to_naive_date_time(&self) -> NaiveDateTime {
//         self.0.naive_utc()
//     }
// }

// impl<'de> Deserialize<'de> for NumericDate {
//     fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
//     where
//         D: serde::Deserializer<'de>,
//     {
//         let i = i64::deserialize(deserializer)?;
//         let dt = NaiveDateTime::from_timestamp_opt(i, 0)
//             .ok_or_else(|| serde::de::Error::custom(format!("invalid timestamp: {i}")))?;
//         Ok(Self(DateTime::from_utc(dt, chrono::Utc)))
//     }
// }
// impl From<NaiveDateTime> for NumericDate {
//     fn from(dt: NaiveDateTime) -> Self {
//         Self(DateTime::from_utc(dt, chrono::Utc))
//     }
// }
// impl From<DateTime<Utc>> for NumericDate {
//     fn from(dt: DateTime<Utc>) -> Self {
//         Self(dt)
//     }
// }
// impl TryFrom<i64> for NumericDate {
//     type Error = InvalidNumericDateError;
//     fn try_from(i: i64) -> Result<Self, Self::Error> {
//         let dt = NaiveDateTime::from_timestamp_opt(i, 0).ok_or(i)?;
//         Ok(Self(DateTime::from_utc(dt, chrono::Utc)))
//     }
// }

// impl TryFrom<u64> for NumericDate {
//     type Error = InvalidNumericDateError;
//     fn try_from(u: u64) -> Result<Self, Self::Error> {
//         let i: i64 = u.try_into().map_err(|_| u)?;
//         Self::try_from(i)
//     }
// }

// #[cfg(feature = "time")]
// impl From<time::PrimitiveDateTime> for NumericDate {
//     fn from(dt: time::PrimitiveDateTime) -> Self {
//         Self(DateTime::from_utc(dt.naive_utc(), chrono::Utc))
//     }
// }

// #[cfg(feature = "std")]
// impl TryFrom<std::time::SystemTime> for NumericDate {
//     type Error = InvalidNumericDateError;
//     fn try_from(st: std::time::SystemTime) -> Result<Self, Self::Error> {
//         st.duration_since(UNIX_EPOCH)?.as_secs().try_into()
//     }
// }
