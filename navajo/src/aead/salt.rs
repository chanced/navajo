use bytes::Bytes;
use ring::{hkdf, hmac};

#[derive(Clone)]
pub(super) struct Salt {
    pub(super) key: hmac::Key,
    pub(super) bytes: Bytes,
    pub(super) algorithm: hkdf::Algorithm,
}

impl Salt {
    pub(super) fn new(algorithm: hkdf::Algorithm, value: impl Into<Bytes>) -> Self {
        let bytes = value.into();
        let hmac_algorithm = if algorithm == hkdf::HKDF_SHA256 {
            hmac::HMAC_SHA256
        } else if algorithm == hkdf::HKDF_SHA384 {
            hmac::HMAC_SHA384
        } else if algorithm == hkdf::HKDF_SHA512 {
            hmac::HMAC_SHA512
        } else {
            // safety: this should never be reached.
            unreachable!(
                "stream salt's hkdf algorithm was not SHA256, SHA384, or SHA512; got {:?}",
                algorithm
            )
        };

        let key = hmac::Key::new(hmac_algorithm, &bytes);
        Self {
            key,
            bytes,
            algorithm,
        }
    }
    pub(super) fn algorithm(&self) -> hkdf::Algorithm {
        self.algorithm
    }
    // pub(super) fn bytes(&self) -> &[u8] {
    //     &self.bytes
    // }
    pub(super) fn extract(&self, secret: &[u8]) -> hkdf::Prk {
        let prk = hmac::sign(&self.key, secret);
        hkdf::Prk::new_less_safe(self.algorithm, prk.as_ref())
    }
}
