mod algorithm;
mod curve;
mod header;
mod jwk;
mod key_operation;
mod key_type;
mod key_use;
mod zip;

pub use algorithm::Algorithm;
pub use curve::Curve;
pub use header::Header;
pub use jwk::{Jwk, Jwks};
pub use key_operation::KeyOperation;
pub use key_type::KeyType;
pub use key_use::KeyUse;
pub use zip::Zip;

#[cfg(test)]
mod tests {
    use crate::rand;

    use super::*;

    #[test]
    fn test_serialize() {
        let mut x = [0u8; 64];
        rand::SystemRng.fill(&mut x).unwrap();
        let mut y = [0u8; 64];
        rand::SystemRng.fill(&mut y).unwrap();

        let jwk = Jwk {
            x: Some(y[..].to_vec()),
            y: Some(x[..].to_vec()),
            x5c: Some(vec![
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
        println!("{str}");
        let jwk2: Jwk = serde_json::from_str(&str).unwrap();

        assert_eq!(jwk, jwk2)
    }
}
