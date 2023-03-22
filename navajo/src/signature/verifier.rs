use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Verifier {}
impl Verifier {
    pub(crate) fn from_keyring(
        keyring: crate::keyring::Keyring<super::signing_key::SigningKey>,
    ) -> Self {
        todo!()
    }
}
