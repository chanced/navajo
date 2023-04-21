// #![warn(missing_docs)]
#![doc = include_str!("../README.md")]
#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

mod aad;
pub use aad::Aad;

#[cfg(feature = "aead")]
pub mod aead;
#[cfg(feature = "aead")]
pub use aead::Aead;

mod buffer;
pub use buffer::Buffer;

pub mod constant_time;
#[cfg(feature = "daead")]
pub mod daead;
#[cfg(feature = "daead")]
pub use daead::Daead;

pub mod envelope;
pub use envelope::{Envelope, PlaintextJson};

pub mod error;

#[cfg(feature = "hkdf")]
pub mod hkdf;

mod id;
#[cfg(feature = "primitive")]
mod key;

#[cfg(feature = "primitive")]
pub(crate) use key::{Key, KeyMaterial};

#[cfg(feature = "primitive")]
#[cfg(feature = "primitive")]
mod keyring_info;

#[cfg(feature = "primitive")]
pub use keyring_info::KeyringInfo;

#[cfg(feature = "primitive")]
mod keyring;

#[cfg(feature = "primitive")]
pub(crate) use keyring::Keyring;

#[cfg(feature = "primitive")]
#[cfg(feature = "mac")]
pub mod mac;

#[cfg(feature = "mac")]
pub use mac::Mac;

mod origin;
pub use origin::Origin;

#[cfg(feature = "primitive")]
pub mod primitive;
#[cfg(feature = "primitive")]
pub use primitive::{Kind, Primitive};

pub mod rand;
pub use rand::{Rng, SystemRng};

pub mod sensitive;

mod status;
pub use status::Status;

#[cfg(feature = "dsa")]
pub mod dsa;

#[cfg(feature = "dsa")]
pub use dsa::{Signer, Verifier};

pub(crate) mod b64;

pub(crate) const NEW_ISSUE_URL: &str = "https://github.com/chanced/navajo/issues/new";

pub(crate) mod sealed;

pub mod secret_store;

pub mod jose;

pub(crate) mod strings;

pub mod metadata;
pub use metadata::{Metadata, RESERVED_METADATA_KEYS};
