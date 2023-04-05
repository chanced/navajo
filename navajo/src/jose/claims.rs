use alloc::{borrow::Cow, string::String};
use derive_builder::Builder;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use super::{NumericDate, StringOrStrings};

#[derive(Debug, PartialEq, Eq, Serialize, Clone, Deserialize, Builder, Default)]
pub struct Claims {
    /// The "iss" (issuer) claim identifies the principal that issued the
    /// JWT.  The processing of this claim is generally application specific.
    /// The `"iss"` value is a case-sensitive string containing a StringOrURI
    /// value.
    ///
    /// Use of this claim is OPTIONAL.
    ///
    /// <https://www.rfc-editor.org/rfc/rfc7519#section-4.1.1>
    #[serde(rename = "iss", skip_serializing_if = "Option::is_none")]
    #[builder(default, setter(into, strip_option))]
    pub issuer: Option<String>,

    /// The `"sub"` (subject) claim identifies the principal that is the
    /// subject of the JWT. The claims in a JWT are normally statements
    /// about the subject. The subject value MUST either be scoped to be
    /// locally unique in the context of the issuer or be globally unique.
    /// The processing of this claim is generally application specific. The
    /// `"sub"` value is a case-sensitive string containing a StringOrURI
    /// value.
    ///
    /// Use of this claim is OPTIONAL.
    ///
    /// <https://www.rfc-editor.org/rfc/rfc7519#section-4.1.2>
    #[serde(rename = "sub", skip_serializing_if = "Option::is_none")]
    #[builder(default, setter(into, strip_option))]
    pub subject: Option<String>,

    /// The `"aud"` (audience) claim identifies the recipients that the JWT is
    /// intended for. Each principal intended to process the JWT MUST
    /// identify itself with a value in the audience claim. If the principal
    /// processing the claim does not identify itself with a value in the
    /// "aud" claim when this claim is present, then the JWT MUST be
    /// rejected. In the general case, the `"aud"` value is an array of case-
    /// sensitive strings, each containing a StringOrURI value.  In the
    /// special case when the JWT has one audience, the `"aud"` value MAY be a
    /// single case-sensitive string containing a StringOrURI value.  The
    /// interpretation of audience values is generally application specific.
    ///
    /// Use of this claim is OPTIONAL.
    ///
    /// <https://www.rfc-editor.org/rfc/rfc7519#section-4.1.3
    #[serde(rename = "aud", skip_serializing_if = "Option::is_none")]
    #[builder(default, setter(into, strip_option))]
    pub audience: Option<StringOrStrings>,

    /// The `"exp"` (expiration time) claim identifies the expiration time on
    /// or after which the JWT MUST NOT be accepted for processing. The
    /// processing of the `"exp"` claim requires that the current date/time
    /// MUST be before the expiration date/time listed in the `"exp"` claim.
    ///
    /// Use of this claim is OPTIONAL.
    ///
    /// https://www.rfc-editor.org/rfc/rfc7519#section-4.1.4
    #[serde(rename = "exp", skip_serializing_if = "Option::is_none")]
    #[builder(default, setter(into, strip_option))]
    pub expiration_time: Option<NumericDate>,

    /// The `"nbf"` (not before) claim identifies the time before which the JWT
    /// MUST NOT be accepted for processing.  The processing of the `"nbf"`
    /// claim requires that the current date/time MUST be after or equal to
    /// the not-before date/time listed in the `"nbf"` claim.  Implementers MAY
    /// provide for some small leeway, usually no more than a few minutes, to
    /// account for clock skew.  Its value MUST be a number containing a
    /// NumericDate value.
    ///
    /// Use of this claim is OPTIONAL.
    ///
    /// <https://www.rfc-editor.org/rfc/rfc7519#section-4.1.5>
    #[serde(rename = "nbf", skip_serializing_if = "Option::is_none")]
    #[builder(default, setter(into, strip_option))]
    pub not_before: Option<NumericDate>,

    /// The `"iat"` (issued at) claim identifies the time at which the JWT was
    /// issued. This claim can be used to determine the age of the JWT.  Its
    /// value MUST be a number containing a NumericDate value.
    ///
    /// Use of this claim is OPTIONAL.
    ///
    /// <https://www.rfc-editor.org/rfc/rfc7519#section-4.1.6>
    #[serde(rename = "iat", skip_serializing_if = "Option::is_none")]
    #[builder(default, setter(into, strip_option))]
    pub issued_at: Option<NumericDate>,

    /// The `"jti"` (JWT ID) claim provides a unique identifier for the JWT.
    /// The identifier value MUST be assigned in a manner that ensures that
    /// there is a negligible probability that the same value will be
    /// accidentally assigned to a different data object; if the application
    /// uses multiple issuers, collisions MUST be prevented among values
    /// produced by different issuers as well.  The "jti" claim can be used
    /// to prevent the JWT from being replayed.  The "jti" value is a case-
    /// sensitive string.
    ///
    /// Use of this claim is OPTIONAL.
    ///
    /// <https://www.rfc-editor.org/rfc/rfc7519#section-4.1.7>
    #[serde(rename = "jti", skip_serializing_if = "Option::is_none")]
    #[builder(default, setter(into, strip_option))]
    pub jwt_id: Option<String>,

    #[serde(flatten)]
    #[builder(default, try_setter, setter)]
    pub additional_claims: serde_json::Map<String, Value>,
}
impl Claims {
    pub fn builder() -> ClaimsBuilder {
        ClaimsBuilder::default()
    }
}
impl From<Claims> for Cow<'static, Claims> {
    fn from(claims: Claims) -> Self {
        Cow::Owned(claims)
    }
}

impl ClaimsBuilder {
    pub fn try_additional_claim<K, V>(
        &mut self,
        key: K,
        value: V,
    ) -> Result<&mut Self, serde_json::Error>
    where
        K: Into<String>,
        V: Serialize,
    {
        let key = key.into();
        let value = serde_json::to_value(value)?;
        Ok(self.additional_claim(key, value))
    }
    pub fn try_issuer<T: TryInto<String>>(mut self, issuer: T) -> Result<Self, T::Error> {
        self.issuer = Some(Some(issuer.try_into()?));
        Ok(self)
    }
    pub fn try_audience<T: TryInto<StringOrStrings>>(
        &mut self,
        aud: T,
    ) -> Result<&mut Self, T::Error> {
        let aud = aud.try_into()?;
        Ok(self.audience(aud))
    }
    pub fn try_expiration_time<T: TryInto<NumericDate>>(
        &mut self,
        exp: T,
    ) -> Result<&mut Self, T::Error> {
        let exp = exp.try_into()?;
        Ok(self.expiration_time(exp))
    }
    pub fn try_not_before<T: TryInto<NumericDate>>(
        &mut self,
        not_before: T,
    ) -> Result<&mut Self, T::Error> {
        Ok(self.expiration_time(not_before.try_into()?))
    }
    pub fn try_issued_at<T: TryInto<NumericDate>>(
        &mut self,
        issued_at: T,
    ) -> Result<&mut Self, T::Error> {
        Ok(self.expiration_time(issued_at.try_into()?))
    }
    pub fn try_jwt_id<T: TryInto<String>>(&mut self, jwt_id: T) -> Result<&mut Self, T::Error> {
        Ok(self.jwt_id(jwt_id.try_into()?))
    }

    pub fn try_subject<T: TryInto<String>>(&mut self, sub: T) -> Result<&mut Self, T::Error> {
        let sub = sub.try_into()?;
        Ok(self.subject(sub))
    }

    pub fn add_audience<T: Into<String>>(mut self, audience: T) -> Self {
        let mut audiences = self.audience.take().flatten();
        if let Some(audiences) = audiences.as_mut() {
            audiences.push(audience.into());
        } else {
            audiences = Some(audience.into().into());
        }
        self.audience = Some(audiences);
        self
    }

    pub fn try_add_audience<T: TryInto<String>>(self, audience: T) -> Result<Self, T::Error> {
        let audience = audience.try_into()?;
        Ok(self.add_audience(audience))
    }

    pub fn additional_claim<K, V>(&mut self, key: K, value: V) -> &mut Self
    where
        K: Into<String>,
        V: Into<Value>,
    {
        let key = key.into();
        let mut additional_claims = self
            .additional_claims
            .take()
            .unwrap_or(serde_json::Map::new());
        additional_claims.insert(key, value.into());
        self.additional_claims = Some(additional_claims);
        self
    }
}

#[cfg(test)]
mod tests {
    use alloc::vec;

    use super::*;

    #[test]
    fn test_builder_additional_claim() {
        let claims = Claims::builder()
            .additional_claim("key1", "example value")
            .additional_claim("key2", 3)
            .audience(vec!["aud1", "aud2"])
            .build()
            .unwrap();

        let mut expected = serde_json::Map::new();
        expected.insert("key1".to_string(), "example value".into());
        expected.insert("key2".to_string(), 3.into());
        assert_eq!(claims.additional_claims, expected);

        assert_eq!(
            claims.audience,
            Some(StringOrStrings::Strings(vec![
                "aud1".to_string(),
                "aud2".to_string()
            ]))
        );
    }
}
