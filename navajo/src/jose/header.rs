use alloc::borrow::Cow;
use serde::{Deserialize, Serialize};

use super::Algorithm;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Header<'a> {
    /// Specifies the cryptographic algorithm used to secure the JWT.
    #[serde(rename = "alg")]
    pub algorithm: Algorithm,

    /// Specifies the type of the token. The value of this field is typically
    /// "JWT" to indicate that the token is a JSON Web Token.
    #[serde(rename = "kid", skip_serializing_if = "Option::is_none")]
    pub key_id: Option<Cow<'a, String>>,

    /// Specifies the media type of the data contained within the JWT. The value
    /// of this field is typically "JWT" to indicate that the data is a JSON Web
    /// Token.
    pub content_type: Option<String>,
}
