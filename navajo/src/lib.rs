#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

mod keyring;
pub(crate) use keyring::Keyring;

mod key;
pub(crate) use key::{Key, KeyMaterial};

pub mod aead;
// pub use aead::Aead;

pub mod error;

mod id;

mod rand;
pub use rand::Random;

mod timestamp;

pub mod hkdf;

pub mod mac;
pub use mac::Mac;

pub mod constant_time;

pub mod aes;

mod kms;
pub use kms::{Kms, KmsSync};

mod origin;
pub use origin::Origin;

mod status;
pub use status::Status;

mod key_info;
pub use key_info::KeyInfo;
