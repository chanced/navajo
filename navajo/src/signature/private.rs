use zeroize::ZeroizeOnDrop;

use crate::{
    error::{KeyError, MalformedError},
    sensitive,
};

use super::Algorithm;

pub struct Key {
    pkcs8: sensitive::Bytes,
    signing_key: SigningKey,
}

enum SigningKey {
    Ed25519(Ed25519),
    Ecdsa(Ecdsa),
    RsaPss(RsaPss),
    RsaSsa(RsaSsa),
}

#[cfg(feature = "ring")]
#[derive(Debug)]
struct Ecdsa {
    signing_key: ring::signature::EcdsaKeyPair,
}
#[cfg(not(feature = "ring"))]
enum Ecdsa {
    P256(p256::ecdsa::SigningKey),
    P384(p384::ecdsa::SigningKey),
}

impl Ecdsa {
    fn from_pkcs8(algorithm: Algorithm, pkcs8: &[u8]) -> Result<Self, KeyError> {
        #[cfg(feature = "ring")]
        {
            let signing_key =
                ring::signature::EcdsaKeyPair::from_pkcs8(algorithm.ring_ecdsa_signing(), pkcs8)?;
            Ok(Self { signing_key })
        }
        #[cfg(not(feature = "ring"))]
        {
            let signing_key = match algorithm {
                Algorithm::Es256 => {
                    use p256::{ecdsa::SigningKey, pkcs8::DecodePrivateKey};
                    let signing_key = SigningKey::from_pkcs8_der(pkcs8)?;
                    Self::P256(signing_key)
                }
                Algorithm::Es384 => {
                    use p384::{ecdsa::SigningKey, pkcs8::DecodePrivateKey};
                    let signing_key = SigningKey::from_pkcs8_der(pkcs8)?;
                    Self::P384(signing_key)
                }
                _ => unreachable!(),
            };
            Ok(signing_key)
        }
    }
}

struct RsaPss {}
struct RsaSsa {}
struct Ed25519 {}
