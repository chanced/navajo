// #![warn(missing_docs)]
#![doc = include_str!("../README.md")]
#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

mod aad;
pub use aad::Aad;

pub mod aead;
pub use aead::Aead;

mod buffer;
pub use buffer::Buffer;

pub mod constant_time;

pub mod daead;
pub use daead::Daead;

pub mod envelope;
pub use envelope::{CleartextJson, Envelope};

pub mod error;
pub mod hkdf;

mod id;

mod key;
pub(crate) use key::{Key, KeyMaterial};

mod key_info;
pub use key_info::KeyInfo;

mod keyring;
pub(crate) use keyring::Keyring;

pub mod mac;
pub use mac::Mac;

mod origin;
pub use origin::Origin;

pub mod primitive;

pub mod rand;
pub use rand::Random;

mod sensitive;

mod status;
pub use status::Status;

pub mod signature;
pub use signature::{Signer, Verifier};

mod timestamp;

pub(crate) mod b64;
