use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum KeyType {
    /// RSA
    Rsa,
    /// Elliptic Curve
    Ec,
    /// Octet Sequence (used to represent symmetric keys)
    Oct,
    /// Octet Key Pair
    Okp,
}
