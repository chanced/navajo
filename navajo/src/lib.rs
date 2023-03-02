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
pub use envelope::{CleartextJson, Envelope};

pub mod error;

#[cfg(feature = "hkdf")]
pub mod hkdf;

mod id;
#[cfg(any(
    feature = "aead",
    feature = "daead",
    feature = "mac",
    feature = "signature",
))]
mod key;
#[cfg(any(
    feature = "aead",
    feature = "daead",
    feature = "mac",
    feature = "signature",
))]
pub(crate) use key::{Key, KeyMaterial};
#[cfg(any(
    feature = "aead",
    feature = "daead",
    feature = "mac",
    feature = "signature",
))]
mod key_info;
#[cfg(any(
    feature = "aead",
    feature = "daead",
    feature = "mac",
    feature = "signature",
))]
pub use key_info::KeyInfo;

#[cfg(any(
    feature = "aead",
    feature = "daead",
    feature = "mac",
    feature = "signature",
))]
mod keyring;
#[cfg(any(
    feature = "aead",
    feature = "daead",
    feature = "mac",
    feature = "signature",
))]
pub(crate) use keyring::Keyring;

#[cfg(feature = "mac")]
pub mod mac;
#[cfg(feature = "mac")]
pub use mac::Mac;

mod origin;
pub use origin::Origin;

#[cfg(any(
    feature = "aead",
    feature = "daead",
    feature = "mac",
    feature = "signature",
))]
pub mod primitive;

pub mod rand;
pub use rand::{Rng, SystemRng};

pub mod sensitive;

mod status;
pub use status::Status;

#[cfg(feature = "signature")]
pub mod signature;
#[cfg(feature = "signature")]
pub use signature::{Signer, Verifier};

pub(crate) mod b64;

pub(crate) const NEW_ISSUE_URL: &str = "https://github.com/chanced/navajo/issues/new";

pub(crate) mod sealed;
