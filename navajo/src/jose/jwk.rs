use super::{Algorithm, Curve, KeyOperation, KeyType, KeyUse};
use crate::{
    b64,
    dsa::{self},
};
use alloc::{string::String, vec::Vec};
use serde::{Deserialize, Serialize};

#[derive(Default, Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Jwk {
    #[serde(rename = "kid", skip_serializing_if = "Option::is_none")]
    pub key_id: Option<String>,

    #[serde(rename = "alg", skip_serializing_if = "Option::is_none", default)]
    pub algorithm: Option<Algorithm>,

    /// The `"kty"` (key type) parameter identifies the cryptographic algorithm
    /// family used with the key, such as "RSA" or "EC". `"kty"` values should
    /// either be registered in the IANA "JSON Web Key Types" registry
    /// established by [JWA] or be a value that contains a Collision-
    /// Resistant Name.  The `"kty"` value is a case-sensitive string.  This
    /// member MUST be present in a JWK.
    ///
    /// required
    ///
    /// <https://www.rfc-editor.org/rfc/rfc7517#section-4.1>
    #[serde(rename = "kty", skip_serializing_if = "Option::is_none", default)]
    pub key_type: Option<KeyType>,

    /// The `"use"` (public key use) parameter identifies the intended use of
    /// the public key.  The "use" parameter is employed to indicate whether
    /// a public key is used for encrypting data or verifying the signature
    /// on data.
    ///
    /// Values defined by this specification are:
    ///
    /// -  `"sig"` (signature)
    /// -  `"enc"` (encryption)
    ///
    /// Other values MAY be used.  The "use" value is a case-sensitive
    /// string.  Use of the "use" member is OPTIONAL, unless the application
    /// requires its presence.
    ///
    /// When a key is used to wrap another key and a public key use
    /// designation for the first key is desired, the "enc" (encryption) key
    /// use value is used, since key wrapping is a kind of encryption. The
    /// "enc" value is also to be used for public keys used for key agreement
    /// operations.
    #[serde(rename = "use", skip_serializing_if = "Option::is_none")]
    pub key_use: Option<KeyUse>,

    /// The `"key_ops"` (key operations) parameter identifies the operation(s) for
    /// which the key is intended to be used.  The `"key_ops"` parameter is
    /// intended for use cases in which public, private, or symmetric keys may
    /// be present.
    ///
    /// Its value is an array of key operation values.  Values defined by this
    /// specification are:
    ///
    /// -  `"sign"` (compute digital signature or MAC)
    /// -  `"verify"` (verify digital signature or MAC)
    /// -  `"encrypt"` (encrypt content)
    /// -  `"decrypt"` (decrypt content and validate decryption, if applicable)
    /// -  `"wrapKey"` (encrypt key)
    /// -  `"unwrapKey"` (decrypt key and validate decryption, if applicable)
    /// -  `"deriveKey"` (derive key)
    /// -  `"deriveBits"` (derive bits not to be used as a key)
    ///
    /// (Note that the "key_ops" values intentionally match the "KeyUsage"
    /// values defined in the Web Cryptography API [W3C.CR-WebCryptoAPI-20141211
    /// specification](https://www.rfc-editor.org/rfc/rfc7517#ref-W3C.CR-WebCryptoAPI-20141211)
    /// .)
    ///
    /// Other values MAY be used.  The key operation values are case- sensitive
    /// strings.  Duplicate key operation values MUST NOT be present in the
    /// array.  Use of the "key_ops" member is OPTIONAL, unless the application
    /// requires its presence.
    ///
    /// Multiple unrelated key operations SHOULD NOT be specified for a key
    /// because of the potential vulnerabilities associated with using the same
    /// key with multiple algorithms.  Thus, the combinations "sign" with
    /// "verify", "encrypt" with "decrypt", and "wrapKey" with "unwrapKey" are
    /// permitted, but other combinations SHOULD NOT be used.
    ///
    /// Additional `"key_ops"` (key operations) values can be registered in the
    /// IANA "JSON Web Key Operations" registry established by Section 8.3. The
    /// same considerations about registering extension values apply to the
    /// `"key_ops"` member as do for the "use" member.
    ///
    /// The `"use"` and `"key_ops"` JWK members SHOULD NOT be used together;
    /// however, if both are used, the information they convey MUST be
    /// consistent.  Applications should specify which of these members they
    /// use, if either is to be used by the application.
    ///
    /// <https://www.rfc-editor.org/rfc/rfc7517#section-4.2>
    #[serde(rename = "key_ops", skip_serializing_if = "Vec::is_empty", default)]
    pub key_operations: Vec<KeyOperation>,

    #[serde(rename = "crv", skip_serializing_if = "Option::is_none", default)]
    pub curve: Option<Curve>,

    #[serde(
        with = "b64::optional_url_safe",
        skip_serializing_if = "Option::is_none",
        default
    )]
    pub x: Option<Vec<u8>>,

    /// X coordinate for an EC key.
    #[serde(
        with = "b64::optional_url_safe",
        skip_serializing_if = "Option::is_none",
        default
    )]
    pub y: Option<Vec<u8>>,

    /// Modulus of an RSA key.
    #[serde(
        with = "b64::optional_url_safe",
        skip_serializing_if = "Option::is_none",
        default
    )]
    pub n: Option<Vec<u8>>,

    /// Exponent of an RSA key.
    #[serde(
        with = "b64::optional_url_safe",
        skip_serializing_if = "Option::is_none",
        default
    )]
    pub e: Option<Vec<u8>>,

    /// Private exponent of an RSA key.
    #[serde(
        with = "b64::optional_url_safe",
        skip_serializing_if = "Option::is_none",
        default
    )]
    pub d: Option<Vec<u8>>,

    #[serde(
        with = "b64::optional_url_safe",
        skip_serializing_if = "Option::is_none",
        default
    )]
    pub p: Option<Vec<u8>>,

    #[serde(
        with = "b64::optional_url_safe",
        skip_serializing_if = "Option::is_none",
        default
    )]
    pub q: Option<Vec<u8>>,

    #[serde(
        with = "b64::optional_url_safe",
        skip_serializing_if = "Option::is_none",
        default
    )]
    pub dp: Option<Vec<u8>>,

    #[serde(
        with = "b64::optional_url_safe",
        skip_serializing_if = "Option::is_none",
        default
    )]
    pub dq: Option<Vec<u8>>,

    #[serde(
        with = "b64::optional_url_safe",
        skip_serializing_if = "Option::is_none",
        default
    )]
    pub qi: Option<Vec<u8>>,

    /// The "x5u" (X.509 URL) parameter is a URI
    /// [RFC3986](https://www.rfc-editor.org/rfc/rfc3986) that refers to a
    /// resource for an X.509 public key certificate or certificate chain
    /// [RFC5280](https://www.rfc-editor.org/rfc/rfc5280).  The identified
    /// resource MUST provide a representation of the certificate or certificate
    /// chain that conforms to [RFC5280](https://www.rfc-editor.org/rfc/rfc5280)
    /// in PEM-encoded form, with each certificate delimited as specified in
    /// [Section 6.1 of
    /// RFC4945](https://www.rfc-editor.org/rfc/rfc4945#section-6.1). The key in
    /// the first certificate MUST match the public key represented by other
    /// members of the JWK.  The protocol used to acquire the resource MUST
    /// provide integrity protection; an HTTP GET request to retrieve the
    /// certificate MUST use TLS
    /// [RFC2818](https://www.rfc-editor.org/rfc/rfc2818)
    /// [RFC5246](https://www.rfc-editor.org/rfc/rfc5246); the identity of the
    /// server MUST be validated, as per [Section 6 of
    /// RFC6125](https://www.rfc-editor.org/rfc/rfc6125#section-6). Use of this
    /// member is OPTIONAL.
    ///
    /// While there is no requirement that optional JWK members providing key
    /// usage, algorithm, or other information be present when the "x5u" member
    /// is used, doing so may improve interoperability for applications that do
    /// not handle PKIX certificates
    /// [RFC5280](https://www.rfc-editor.org/rfc/rfc5280). If other members are
    /// present, the contents of those members MUST be semantically consistent
    /// with the related fields in the first certificate.  For instance, if the
    /// "use" member is present, then it MUST correspond to the usage that is
    /// specified in the certificate, when it includes this information.
    /// Similarly, if the "alg" member is present, it MUST correspond to the
    /// algorithm specified in the certificate.
    #[serde(rename = "x5u", skip_serializing_if = "Option::is_none")]
    pub x509_url: Option<url::Url>,

    /// The `"x5c"` (X.509 certificate chain) parameter contains a chain of one or
    /// more PKIX certificates
    /// [RFC5280](https://www.rfc-editor.org/rfc/rfc5280).  The certificate
    /// chain is represented as a JSON array of certificate value strings.  Each
    /// string in the array is a base64-encoded \([Section 4 of
    /// RFC4648](https://www.rfc-editor.org/rfc/rfc4648#section-4) -- not
    /// base64url-encoded) DER
    /// [ITU.X690.1994](https://www.rfc-editor.org/rfc/rfc7517#ref-ITU.X690.1994)
    /// PKIX certificate value. The PKIX certificate containing the key value
    /// MUST be the first certificate. This MAY be followed by additional
    /// certificates, with each subsequent certificate being the one used to
    /// certify the previous one.  The key in the first certificate MUST match
    /// the public key represented by other members of the JWK.  Use of this
    /// member is OPTIONAL.
    ///
    /// As with the "x5u" member, optional JWK members providing key usage,
    /// algorithm, or other information MAY also be present when the "x5c"
    /// member is used.  If other members are present, the contents of those
    /// members MUST be semantically consistent with the related fields in the
    /// first certificate.  See the last paragraph of [Section
    /// 4.6](https://www.rfc-editor.org/rfc/rfc7517#section-4.6) for additional
    /// guidance on this.
    #[serde(
        rename = "x5c",
        with = "b64::optional_seq_url_safe",
        skip_serializing_if = "Option::is_none",
        default
    )]
    pub x509_cert_chain: Option<Vec<Vec<u8>>>,

    /// The `"x5t"` (X.509 certificate SHA-1 thumbprint) parameter is a
    /// base64url-encoded SHA-1 thumbprint (a.k.a. digest) of the DER
    /// encoding of an X.509 certificate [RFC5280].  Note that certificate
    /// thumbprints are also sometimes known as certificate fingerprints.
    /// The key in the certificate MUST match the public key represented by
    /// other members of the JWK.  Use of this member is OPTIONAL.
    ///
    /// As with the "x5u" member, optional JWK members providing key usage,
    /// algorithm, or other information MAY also be present when the "x5t"
    /// member is used.  If other members are present, the contents of those
    /// members MUST be semantically consistent with the related fields in
    /// the referenced certificate.  See the last paragraph of Section 4.6
    /// for additional guidance on this.
    #[serde(
        rename = "x5t",
        with = "b64::optional_url_safe",
        skip_serializing_if = "Option::is_none",
        default
    )]
    pub x509_cert_sha1_thumbprint: Option<Vec<u8>>,

    /// The `"x5t#S256"` (X.509 certificate SHA-256 thumbprint) parameter is a
    /// base64url-encoded SHA-256 thumbprint (a.k.a. digest) of the DER encoding
    /// of an X.509 certificate [RFC5280].  Note that certificate thumbprints
    /// are also sometimes known as certificate fingerprints. The key in the
    /// certificate MUST match the public key represented by other members of
    /// the JWK.  Use of this member is OPTIONAL.
    ///
    /// As with the "x5u" member, optional JWK members providing key usage,
    /// algorithm, or other information MAY also be present when the "x5t#S256"
    /// member is used.  If other members are present, the contents of those
    /// members MUST be semantically consistent with the related fields in the
    /// referenced certificate.  See the last paragraph of [Section
    /// 4.6](https://www.rfc-editor.org/rfc/rfc7517#section-4.6) for additional
    /// guidance on this.
    ///
    /// <https://www.rfc-editor.org/rfc/rfc7517#section-4.9>
    #[serde(
        rename = "x5t#S256",
        with = "b64::optional_url_safe",
        skip_serializing_if = "Option::is_none",
        default
    )]
    pub x509_cert_sha256_thumbprint: Option<Vec<u8>>,

    ///
    /// Unknown, additional fields found in the JWK
    #[serde(flatten, default)]
    pub additional_fields: serde_json::Map<String, serde_json::Value>,
}

impl Jwk {
    /// Returns the [`Algorithm`] of the JWK, determined by either the `"alg"`
    /// property or the `"kty"` and, if relevant, the `"crv"` properties.
    pub fn algorithm(&self) -> Option<Algorithm> {
        if let Some(alg) = self.algorithm {
            return Some(alg);
        }
        let kty = self.key_type?;
        let curve = self.curve?;
        match kty {
            KeyType::Ec => Algorithm::try_from((kty, curve)).ok(),
            KeyType::Okp => Algorithm::try_from((kty, curve)).ok(),
            _ => None,
        }
    }

    pub fn dsa_algorithm(&self) -> Option<dsa::Algorithm> {
        let alg = self.algorithm()?;
        match alg {
            Algorithm::Es256 => Some(dsa::Algorithm::Es256),
            Algorithm::Es384 => Some(dsa::Algorithm::Es384),
            Algorithm::EdDsa => {
                let curve = self.curve?;
                match curve {
                    Curve::Ed25519 => Some(dsa::Algorithm::Ed25519),
                    _ => None,
                }
            }
            _ => None,
        }
    }
}
impl TryInto<dsa::Algorithm> for &Jwk {
    type Error = &'static str;

    fn try_into(self) -> Result<dsa::Algorithm, Self::Error> {
        self.dsa_algorithm()
            .ok_or("unable to determine signature algorithm")
    }
}
pub type Jwks = Vec<Jwk>;

#[cfg(test)]
mod tests {
    use alloc::vec;

    use crate::rand;

    use super::*;

    #[test]
    fn test_serialize_jwk() {
        let mut x = [0u8; 64];
        rand::SystemRng.fill(&mut x).unwrap();
        let mut y = [0u8; 64];
        rand::SystemRng.fill(&mut y).unwrap();

        let jwk = Jwk {
            x: Some(y[..].to_vec()),
            y: Some(x[..].to_vec()),
            x509_cert_chain: Some(vec![
                vec![0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
                vec![1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1],
                vec![2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2],
                vec![3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3],
                vec![4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4],
                vec![5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5],
                vec![6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6],
                vec![7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7],
            ]),
            ..Default::default()
        };

        let str = serde_json::to_string_pretty(&jwk).unwrap();
        let jwk2: Jwk = serde_json::from_str(&str).unwrap();

        assert_eq!(jwk, jwk2)
    }
}
