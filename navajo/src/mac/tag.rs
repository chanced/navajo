use alloc::sync::{Arc, Weak};

/// Tags are used to verify the integrity of data. They are generated for each
/// active key within the keyring at the point of computation. If new keys are
/// added to the keyring, tags can be updated by calling
/// [`update`](Self::update), [`read_update`](Self::read_update), or
/// [`stream_update`](Self::stream_update).
///
/// When a key is deleted from the keyring, the computed tag for that given key
/// will no longer be evaluated. Note though that the computed data remains in
/// memory. If the `Tag` is not updated after all keys have been deleted, all
/// attempts to [`verify`](Self::verify) will fail, returning a
/// [`MacError::NoTagsAvailabe`](crate::error::MacError).
///
/// If the keyring is composed of a single key and that fact will not change
/// through the life of the application, it will be more efficient to use the
/// tag as bytes by calling [`truncate(size).as_bytes()`](Self::truncate),
/// [`as_bytes`](Self::as_bytes) or [`as_ref`](Self::as_ref). and evaluating the
/// tag directly with
/// [`constant_time::verify_slices_are_equal`](crate::constant_time::verify_slices_are_equal).
/// ## Examples
#[derive(Clone)]
pub struct Tag {
    entries: Vec<Arc<Entry>>,
    primary: Arc<Entry>,
}

#[derive(Clone)]
struct Entry {
    key: Weak<super::Key>,
    output: Output,
}

impl Entry {
    pub(super) fn new(key: &Arc<super::Key>, output: Output) -> Self {
        Self {
            key: Arc::downgrade(key),
            output,
        }
    }
    pub(super) fn truncatable(&self) -> bool {
        self.output.truncatable()
    }
    pub(super) fn truncate(&self, len: usize) -> Result<TruncatedTag, TruncationError> {
        // todo: validate len
        Ok(TruncatedTag {
            tag: self.clone(),
            len,
        })
    }
    pub fn verify(&self, other: &[u8]) -> Result<(), MacError> {
        todo!()
    }
}

impl AsRef<[u8]> for Entry {
    fn as_ref(&self) -> &[u8] {
        self.output.as_ref()
    }
}

#[derive(Clone)]
pub struct TruncatedTag {
    tag: Entry,
    len: usize,
}

impl AsRef<[u8]> for TruncatedTag {
    fn as_ref(&self) -> &[u8] {
        &self.tag.as_ref()[..self.len]
    }
}

pub(super) trait DigestOutput: AsRef<[u8]> + Clone {
    fn into_bytes(self) -> Vec<u8> {
        self.as_ref().to_vec()
    }
    fn truncatable(&self) -> bool;
}

#[derive(Clone)]
pub(super) enum Output {
    #[cfg(all(feature = "ring", feature = "hmac_sha2"))]
    Ring(RingOutput),
    RustCrypto(crate::mac::RustCryptoOutput),
    #[cfg(feature = "blake3")]
    Blake3(Blake3Output),
}

impl DigestOutput for Output {
    fn truncatable(&self) -> bool {
        match self {
            #[cfg(all(feature = "ring", feature = "hmac_sha2"))]
            Self::Ring(output) => output.truncatable(),
            Self::RustCrypto(output) => output.truncatable(),
            Self::Blake3(output) => output.truncatable(),
        }
    }
}
impl AsRef<[u8]> for Output {
    fn as_ref(&self) -> &[u8] {
        match self {
            #[cfg(all(feature = "ring", feature = "hmac_sha2"))]
            Self::Ring(output) => output.as_ref(),
            Self::RustCrypto(output) => output.as_ref(),
            Self::Blake3(output) => output.as_ref(),
        }
    }
}

cfg_if::cfg_if! {
    if #[cfg(all(feature = "ring", feature="hmac_sha2"))] {
        #[derive(Clone)]
        pub(super) struct RingOutput(ring_compat::ring::hmac::Tag);
        impl AsRef<[u8]> for RingOutput {
            fn as_ref(&self) -> &[u8] {
                self.0.as_ref()
            }
        }
        impl DigestOutput for RingOutput {
            fn truncatable(&self) -> bool { true }
        }
        impl From<ring_compat::ring::hmac::Tag> for Output {
            fn from(output: ring_compat::ring::hmac::Tag) -> Self {
                Self::Ring(RingOutput(output))
            }
        }
    }

}

cfg_if::cfg_if! {
    if #[cfg(feature = "blake3")] {
        #[derive(Clone)]
        pub(super) struct Blake3Output (blake3::Hash);
        impl DigestOutput for Blake3Output {
            fn truncatable(&self) -> bool { true } //github.com/BLAKE3-team/BLAKE3/issues/123
        }
        impl From<blake3::Hash> for Blake3Output {
            fn from(hash: blake3::Hash) -> Self {
                Self(hash)
            }
        }
        impl AsRef<[u8]> for Blake3Output {
            fn as_ref(&self) -> &[u8] {
                self.0.as_bytes()
            }
        }
        impl From<Blake3Output> for Output {
            fn from(output: Blake3Output) -> Self {
                Self::Blake3(output)
            }
        }
    }
}

macro_rules! rust_crypto_internal_tag {
    ($typ:ident, $crt:ident, $alg:ident, $feat:meta$(, not($cfg:meta))?) => {
        paste::paste! {
            cfg_if::cfg_if! {
                if #[cfg(all($feat, $(not($cfg))?))] {
                    #[derive(Clone)]
                    pub(super) struct [< $typ $alg InternalTag >] (digest::Output<[< $typ:lower >]::$typ<$crt::$alg>>);
                    impl AsRef<[u8]> for [< $typ $alg InternalTag >] {
                        fn as_ref(&self) -> &[u8] {
                            self.0.as_ref()
                        }
                    }
                    impl From<digest::CtOutput<[< $typ:lower >]::$typ<$crt::$alg>>> for [< $typ $alg InternalTag >] {
                        fn from(output: digest::CtOutput<[< $typ:lower >]::$typ<$crt::$alg>>) -> Self {
                            Self(output.into_bytes())
                        }
                    }
                    impl DigestOutput for [< $typ $alg InternalTag >] {
                        fn truncatable(&self) -> bool { true }
                    }
                    impl From<[< $typ $alg InternalTag >]> for Output {
                        fn from(output: [< $typ $alg InternalTag >]) -> Self {
                            RustCryptoOutput::$alg(output).into()
                        }
                    }
                    impl From<digest::CtOutput<[< $typ:lower >]::$typ<$crt::$alg>>> for Output {
                        fn from(output: digest::CtOutput<[< $typ:lower >]::$typ<$crt::$alg>>) -> Self {
                            [< $typ $alg InternalTag >]::from(output).into()
                        }
                    }
                }
            }
        }
    }
}

macro_rules! rust_crypto_internal_tags {
    ({
        hmac: { ring: [$($ring:ident),*], sha2: [$($sha2:ident),*], sha3: [$($sha3:ident),*]$(,)? },
        cmac: { aes: [$($aes:ident),*]$(,)? }
	}) => {
        paste::paste! {
            #[derive(Clone)]
            pub(super) enum RustCryptoOutput {
                $(
                    #[cfg(all(feature="hmac_sha2", not(feature = "ring")))]
                    $ring(crate::mac::[< Hmac $ring InternalTag >]),
                )*
                $(
                    #[cfg(feature="hmac_sha2")]
                    $sha2(crate::mac::[< Hmac $sha2 InternalTag >]),
                )*

                $(
                    #[cfg(feature="hmac_sha3")]
                    $sha3(crate::mac::[< Hmac $sha3 InternalTag >]),
                )*
                $(
                    #[cfg(feature="cmac_aes")]
                    $aes(crate::mac::[< Cmac $aes InternalTag >]),
                )*
            }
            impl From<RustCryptoOutput> for Output {
                fn from(output: RustCryptoOutput) -> Self {
                    Self::RustCrypto(output)
                }
            }
			$( rust_crypto_internal_tag!(Hmac, sha2, $ring, feature = "hmac_sha2", not(feature="ring")); )*
            $( rust_crypto_internal_tag!(Hmac, sha2, $sha2, feature = "hmac_sha2"); )*
            $( rust_crypto_internal_tag!(Hmac, sha3, $sha3, feature = "hmac_sha3"); )*
            $( rust_crypto_internal_tag!(Cmac, aes, $aes, feature = "cmac_aes"); )*

            impl AsRef<[u8]> for RustCryptoOutput {
                fn as_ref(&self) -> &[u8] {
                    match self {
                        $(
                            #[cfg(not(feature = "ring"))]
                            Self::[< Hmac $ring InternalTag >](tag) => tag.as_ref(),
                        )*
                        $(
                            #[cfg(feature="hmac_sha2")]
                            Self::$sha2(tag) => tag.as_ref(),

                        )*
                        $(
                            #[cfg(feature="hmac_sha3")]
                            Self::$sha3(tag) => tag.as_ref(),
                        )*
                        $(
                            #[cfg(feature="cmac_aes")]
                            Self::$aes(tag) => tag.as_ref(),

                        )*
                    }
                }
            }
            impl crate::mac::tag::DigestOutput for RustCryptoOutput {
                fn truncatable(&self) -> bool { true }
            }
        }
    }
}

pub(super) use rust_crypto_internal_tag;
pub(super) use rust_crypto_internal_tags;

use crate::error::{MacError, TruncationError};
