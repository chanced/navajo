use core::time::Duration;

use alloc::{borrow::ToOwned, string::ToString};
use derive_builder::Builder;

use crate::error::{
    TokenAudienceError, TokenExpiredError, TokenIssuedAtInFutureError, TokenIssuerError,
    TokenNotYetValidError, TokenValidationError,
};

use super::{Claims, NumericDate, StringOrStrings};

#[derive(Debug, Clone, Builder)]
#[cfg_attr(not(feature = "std"), builder(no_std))]
/// Validates a JWS
pub struct Validator<'a> {
    #[builder(default, setter(strip_option))]
    pub expected_issuer: Option<Option<&'a str>>,
    /// - If `"aud"` is a string, then it must match this value.
    /// - If `"aud"` is an array of strings, then it must contain this value.
    #[builder(default, setter(strip_option))]
    pub expected_audience: Option<Option<&'a str>>,

    #[builder(default, setter(strip_option))]
    pub expected_subject: Option<Option<&'a str>>,

    /// The current date and time, in seconds since the Unix epoch.
    #[builder(try_setter, setter)]
    pub now_timestamp: NumericDate,

    /// The maximum clock skew to allow when validating the `exp` and `nbf`
    /// claims.
    ///
    /// This is useful for validating tokens across machines which may have
    /// slightly different clocks. Also, it addresses clock drift.
    ///
    /// While not validated, it is recommended that this value be less than 10
    /// minutes.
    #[builder(try_setter, setter(into))]
    pub clock_skew: core::time::Duration,

    #[builder(default, setter)]
    pub allow_missing_expiration: bool,

    #[builder(default, setter)]
    pub expect_issued_at_in_past: bool,
}

impl<'a> Validator<'a> {
    pub fn builder() -> ValidatorBuilder<'a> {
        ValidatorBuilder::default()
    }
    pub fn validate(&self, claims: &Claims) -> Result<(), TokenValidationError> {
        self.validate_timestamps(claims)?;
        self.validate_audience(claims.audience.as_ref())?;
        self.validate_issuer(claims.issuer.as_deref())?;
        Ok(())
    }

    fn validate_issuer(&self, issuer: Option<&str>) -> Result<(), TokenValidationError> {
        if self.expected_issuer.is_none() {
            return Ok(());
        }
        let expected_issuer = self.expected_issuer.unwrap();
        if let Some(issuer) = issuer {
            match expected_issuer {
                Some(expected) => {
                    if issuer != expected {
                        return Err(TokenIssuerError {
                            expected_issuer: expected_issuer.map(|s| s.to_string()),
                            actual: Some(issuer.to_owned()),
                        }
                        .into());
                    }
                }
                None => {
                    return Err(TokenIssuerError {
                        expected_issuer: None,
                        actual: Some(issuer.to_string()),
                    }
                    .into());
                }
            }
        } else {
            return Err(TokenIssuerError {
                expected_issuer: expected_issuer.map(|s| s.to_string()),
                actual: None,
            }
            .into());
        }
        Ok(())
    }

    fn validate_audience(
        &self,
        audience: Option<&StringOrStrings>,
    ) -> Result<(), TokenValidationError> {
        if self.expected_audience.is_none() {
            return Ok(());
        }
        let expected_audience = self.expected_audience.unwrap();
        if let Some(audience) = audience {
            match expected_audience {
                Some(expected) => {
                    if !audience.contains(expected) {
                        return Err(TokenAudienceError {
                            expected_audience: expected_audience.map(|s| s.to_string()),
                            actual: Some(audience.to_owned()),
                        }
                        .into());
                    }
                }
                None => {
                    return Err(TokenAudienceError {
                        expected_audience: None,
                        actual: Some(audience.to_owned()),
                    }
                    .into())
                }
            }
        } else {
            return Err(TokenAudienceError {
                expected_audience: expected_audience.map(|s| s.to_string()),
                actual: None,
            }
            .into());
        }
        Ok(())
    }
    fn validate_timestamps(&self, claims: &Claims) -> Result<(), TokenValidationError> {
        let now = self.now_timestamp;
        let upper = now + self.clock_skew;
        let lower = now - self.clock_skew;
        let clock_skew = self.clock_skew;

        self.validate_expiration_time(claims.expiration_time, now, lower, clock_skew)?;
        self.validate_not_before(claims.not_before, now, upper, clock_skew)?;
        self.validate_issued_at(claims.issued_at, now, upper, clock_skew)?;

        Ok(())
    }
    fn validate_not_before(
        &self,
        not_before: Option<NumericDate>,
        now: NumericDate,
        upper: NumericDate,
        clock_skew: Duration,
    ) -> Result<(), TokenValidationError> {
        if let Some(not_before) = not_before {
            if not_before > upper {
                return Err(TokenNotYetValidError {
                    not_before,
                    now,
                    clock_skew,
                }
                .into());
            }
        }
        Ok(())
    }
    fn validate_expiration_time(
        &self,
        expiration_time: Option<NumericDate>,
        now: NumericDate,
        lower: NumericDate,
        clock_skew: Duration,
    ) -> Result<(), TokenValidationError> {
        if let Some(expiration_time) = expiration_time {
            if expiration_time < lower {
                return Err(TokenExpiredError {
                    expiration_time,
                    now,
                    clock_skew,
                }
                .into());
            }
        } else if !self.allow_missing_expiration {
            return Err(TokenValidationError::MissingExpiration);
        }

        Ok(())
    }
    fn validate_issued_at(
        &self,
        issued_at: Option<NumericDate>,
        now: NumericDate,
        upper: NumericDate,
        clock_skew: Duration,
    ) -> Result<(), TokenValidationError> {
        if self.expect_issued_at_in_past {
            if let Some(issued_at) = issued_at {
                if issued_at > upper {
                    return Err(TokenIssuedAtInFutureError {
                        issued_at,
                        now,
                        clock_skew,
                    }
                    .into());
                }
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use alloc::vec;

    use super::*;
    const NOW: NumericDate = NumericDate(1680495923);

    #[test]
    fn test_validates_issuer() {
        let v = Validator::builder()
            .expected_issuer(Some("foo"))
            .now_timestamp(NOW)
            .clock_skew(core::time::Duration::from_secs(1))
            .allow_missing_expiration(true)
            .build()
            .unwrap();
        assert!(v
            .validate(&Claims {
                issuer: Some("foo".to_string()),
                ..Default::default()
            })
            .is_ok());

        let err = v
            .validate(&Claims {
                issuer: Some("bar".to_string()),
                ..Default::default()
            })
            .unwrap_err();

        assert_eq!(
            err,
            TokenIssuerError {
                expected_issuer: Some("foo".to_string()),
                actual: Some("bar".to_string()),
            }
            .into()
        );

        let v = Validator::builder()
            .expected_issuer(None)
            .now_timestamp(NOW)
            .clock_skew(core::time::Duration::from_secs(1))
            .allow_missing_expiration(true)
            .build()
            .unwrap();

        let err = v
            .validate(&Claims {
                issuer: Some("bar".to_string()),
                ..Default::default()
            })
            .unwrap_err();
        assert_eq!(
            err,
            TokenIssuerError {
                expected_issuer: None,
                actual: Some("bar".to_string()),
            }
            .into()
        );
    }
    #[test]
    fn test_validates_expiration() {
        let clock_skew = core::time::Duration::from_secs(60);

        let v = Validator::builder()
            .now_timestamp(NOW)
            .clock_skew(clock_skew)
            .allow_missing_expiration(true)
            .build()
            .unwrap();
        assert!(v.validate(&Claims::default()).is_ok());

        let v = Validator::builder()
            .now_timestamp(NOW)
            .clock_skew(clock_skew)
            .build()
            .unwrap();
        assert_eq!(
            v.validate(&Claims::default()),
            Err(TokenValidationError::MissingExpiration)
        );

        assert!(v
            .validate(&Claims::builder().expiration_time(NOW).build().unwrap())
            .is_ok());

        assert!(v
            .validate(
                &Claims::builder()
                    .expiration_time(NOW - clock_skew)
                    .build()
                    .unwrap()
            )
            .is_ok());

        let err = v
            .validate(
                &Claims::builder()
                    .expiration_time(NOW - clock_skew - 1)
                    .build()
                    .unwrap(),
            )
            .unwrap_err();
        assert_eq!(
            err,
            TokenExpiredError {
                expiration_time: NOW - clock_skew - 1,
                now: NOW,
                clock_skew,
            }
            .into()
        );
    }

    #[test]
    fn test_validates_audience() {
        let clock_skew = core::time::Duration::from_secs(60);
        let v = Validator::builder()
            .expected_audience(Some("foo"))
            .now_timestamp(NOW)
            .clock_skew(clock_skew)
            .allow_missing_expiration(true)
            .build()
            .unwrap();
        assert!(v
            .validate(&Claims {
                audience: Some("foo".into()),
                ..Default::default()
            })
            .is_ok());

        assert!(v
            .validate(&Claims {
                audience: Some(vec!["foo", "bar"].into()),
                ..Default::default()
            })
            .is_ok());

        let err = v
            .validate(&Claims {
                audience: Some("bar".into()),
                ..Default::default()
            })
            .unwrap_err();
        assert_eq!(
            err,
            TokenAudienceError {
                expected_audience: Some("foo".to_string()),
                actual: Some("bar".into()),
            }
            .into()
        );

        let v = Validator::builder()
            .expected_audience(None)
            .now_timestamp(NOW)
            .clock_skew(clock_skew)
            .allow_missing_expiration(true)
            .build()
            .unwrap();

        let err = v
            .validate(&Claims {
                audience: Some("bar".into()),
                ..Default::default()
            })
            .unwrap_err();

        assert_eq!(
            err,
            TokenAudienceError {
                expected_audience: None,
                actual: Some("bar".into()),
            }
            .into()
        );
    }

    #[test]
    fn test_validate_not_before() {
        let v = Validator::builder()
            .now_timestamp(NOW)
            .clock_skew(core::time::Duration::from_secs(60))
            .allow_missing_expiration(true)
            .build()
            .unwrap();
        assert!(v.validate(&Claims::default()).is_ok());

        assert!(v
            .validate(&Claims::builder().not_before(NOW).build().unwrap())
            .is_ok());

        assert!(v
            .validate(&Claims::builder().not_before(NOW - 60).build().unwrap())
            .is_ok());
        let err = v
            .validate(&Claims::builder().not_before(NOW + 61).build().unwrap())
            .unwrap_err();
        assert_eq!(
            err,
            TokenNotYetValidError {
                not_before: NOW + 61,
                now: NOW,
                clock_skew: core::time::Duration::from_secs(60),
            }
            .into()
        );
    }

    #[test]
    fn test_validates_issued_at() {
        let v = Validator::builder()
            .now_timestamp(NOW)
            .clock_skew(core::time::Duration::from_secs(60))
            .expect_issued_at_in_past(true)
            .allow_missing_expiration(true)
            .build()
            .unwrap();

        assert!(v
            .validate(&Claims {
                issued_at: Some(NOW - 60),
                ..Default::default()
            })
            .is_ok());

        assert!(v
            .validate(&Claims {
                issued_at: Some(NOW + 60),
                ..Default::default()
            })
            .is_ok());

        let err = v
            .validate(&Claims {
                issued_at: Some(NOW + 61),
                ..Default::default()
            })
            .unwrap_err();
        assert_eq!(
            err,
            TokenIssuedAtInFutureError {
                issued_at: NOW + 61,
                now: NOW,
                clock_skew: core::time::Duration::from_secs(60),
            }
            .into()
        );

        let v = Validator::builder()
            .now_timestamp(NOW)
            .clock_skew(core::time::Duration::from_secs(60))
            .expect_issued_at_in_past(false)
            .allow_missing_expiration(true)
            .build()
            .unwrap();

        assert!(v
            .validate(&Claims {
                issued_at: Some(NOW + 61),
                ..Default::default()
            })
            .is_ok());
    }
}
