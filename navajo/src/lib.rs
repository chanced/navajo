#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

mod keyring;
pub(crate) use keyring::Keyring;

mod key;

pub(crate) use key::{Key, KeyMaterial};
pub use key::{KeyInfo, KeyStatus};

pub mod aead;
// pub use aead::Aead;

pub mod error;

mod id;

mod rand;
pub use rand::Random;

mod timestamp;

pub mod hkdf;

pub mod mac;

pub mod constant_time;

pub mod aes;

mod kms;
pub use kms::{Kms, KmsSync};

mod primitive;
// pub use primitive::{seal, seal_sync, unseal, unseal_sync, Primitive};
