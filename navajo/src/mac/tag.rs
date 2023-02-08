use super::material::Material;

use crate::{
    constant_time::verify_slices_are_equal,
    error::{MacVerificationError, TruncationError},
    Key,
};
use alloc::{sync::Arc, vec::Vec};

/// [`Mac`] `Tag`s are used to verify the integrity of data.
///
/// The `Tag` will contain the the MAC data for each key within the keyring at
/// the point of computation. If new keys are added to the keyring or keys need
/// to be removed, tags can be updated by calling [`update`](Self::update),
/// [`read_update`](Self::read_update), or
/// [`stream_update`](Self::stream_update). This means that even if a key were
/// to be removed from the keyring, the `Tag` will still contain the computed
/// MAC for that key and will continue to be utilized to verify the integrity of
/// data and, in the case of the primary key, be the source of output.
///
///
/// When calling `as_bytes` or `as_ref`, the primary key's output will returned.
/// The default behavior is to return the full MAC with the header prefixed. If
/// navajo generated the key, the MAC will be in the format:
/// ```text
/// || Version (1 byte) || Key ID (4 bytes) || MAC (variable length based on algorithm) ||
/// ```
/// To import a [`Tag`] from another source, such as Tink, the header can be set
/// during construction by passing the prefix as the `prefix` argument to the
/// [`new_with_external_key`](Mac::new_with_external_key) method. If the prefix
/// is not set, the output will be the raw MAC bytes for external keys.
///
/// To truncate the `Tag` to a specific length, a call to
/// [`truncate`](Self::truncate) will clone the tag and assign the truncation
/// size in the returned `Tag`. All uses of resulting `Tag` will be truncated,
/// which includes the output (e.g. [`as_bytes`](Self::as_bytes),
/// [`as_ref`](Self::as_ref)) as well as for verification purposes.
///
/// ## Examples
/// ```rust
/// use navajo::{Mac, Algorithm};
/// let mac = Mac::new(Algorithm::HmacSha256);
/// let tag = mac.compute(b"foo").unwrap();
/// let valid = mac.compute(b"foo").unwrap();
/// assert!(tag.verify(&valid).is_ok());
/// let invalid = mac.compute(b"bar").unwrap();
/// assert!(tag.verify(&invalid).is_err());
/// ```
///
#[derive(Clone)]
pub struct Tag {
    entries: Vec<Arc<Entry>>,
    primary: Arc<Entry>,
    truncate_to: Option<usize>,
    /// If true, the header will be omitted from the output of `as_bytes` and
    /// `as_ref`.
    pub omit_header: bool,
}

impl Tag {
    /// Verifies that `tag` matches the computed MAC for any key in the [`Mac`]
    /// keyring at the point this [`Tag`] was created or last updated.
    ///
    /// ## Example
    /// ```rust
    /// use navajo::{Mac, Algorithm};
    ///
    /// let mac = Mac::new(Algorithm::HmacSha256);
    /// let tag = mac.compute(b"foo").unwrap();
    /// let valid = mac.compute(b"foo").unwrap();
    /// assert!(tag.verify(&valid).is_ok());
    ///
    /// let other_mac = Mac::new(Algorithm::HmacSha256);
    /// let invalid = other_mac.compute(b"foo").unwrap();
    /// assert!(tag.verify(&invalid).is_err());
    ///
    pub fn verify(&self, tag: &[u8]) -> Result<(), MacVerificationError> {
        for entry in &self.entries {
            if entry.verify(tag).is_ok() {
                return Ok(());
            }
        }
        Err(MacVerificationError)
    }
    /// Returns this [`Tag`] cloned without truncation.
    pub fn remove_truncation(&self) -> Self {
        Self {
            omit_header: self.omit_header,
            entries: self.entries.clone(),
            primary: self.primary.clone(),
            truncate_to: None,
        }
    }

    /// Returns this a clone of this `Tag` with a flag set indicating that the
    /// header should be omitted when represented as bytes. Any calls to `as_bytes`
    /// or `as_ref` will return the MAC bytes without the header.
    pub fn omit_header(&self) -> Self {
        Self {
            omit_header: true,
            entries: self.entries.clone(),
            primary: self.primary.clone(),
            truncate_to: self.truncate_to,
        }
    }

    pub fn include_header(&self) -> Self {
        Self {
            omit_header: false,
            entries: self.entries.clone(),
            primary: self.primary.clone(),
            truncate_to: self.truncate_to,
        }
    }
    /// Returns this `Tag` cloned with truncation to `len` bytes if possible.
    ///
    /// Note that the truncation will be applied to entire output. The header of
    /// the `Tag` is 5 bytes. Unless the header is to be omitted (by calling
    /// [`omit_header`]), the bare minimum the `Tag` must be is 13 bytes. If the
    /// omit header flag is set, the minimum length is 8 bytes.
    ///
    /// A value of `0` will remove the truncation, effectively calling
    /// [`remove_truncation`].
    ///
    /// ## Errors
    /// - If `len` is less than 13 and greater than 0, and [`omit_header`] is
    ///   `false`, an error will be returned.
    /// - If `len` is greater than the size of any of the keys in the keyring,
    ///  an error will be returned.
    /// - If an algorithm in the keyset does not permit truncation.
    ///
    /// ## Example
    /// ```rust
    /// use navajo::{Mac, Algorithm};
    /// let mac = Mac::new(Algorithm::HmacSha256);
    /// let tag = mac.compute(b"foo").unwrap();
    /// let truncated = tag.truncate(16).unwrap();
    /// asssert_eq!(truncated.as_bytes().len(), 16);
    /// ```
    pub fn truncate(&self, len: usize) -> Result<Self, TruncationError> {
        if len == 0 {
            return Ok(self.remove_truncation());
        }
        if len < 8 {
            return Err(TruncationError::TooShort);
        }
        if !self.omit_header && len < 13 {
            return Err(TruncationError::TooShort);
        }

        let mut primary: Option<Arc<Entry>> = None;
        let mut entries = Vec::with_capacity(self.entries.len());
        for entry in &self.entries {
            let truncated = Arc::new(entry.truncate(len)?);
            if truncated.key == self.primary.key {
                primary = Some(entry.clone());
            }
            entries.push(truncated);
        }
        let primary = primary.expect("primary key not found during construction of tag\nthis is a bug!\nplease report it: https://github.com/chanced/navajo/issues/new");
        Ok(Self {
            entries,
            primary,
            omit_header: self.omit_header,
            truncate_to: Some(len),
        })
    }
    pub(super) fn new(primary_key: &Key<Material>, output: Vec<(Key<Material>, Output)>) -> Self {
        let mut primary_entry: Option<Arc<Entry>> = None;
        let mut entries = Vec::with_capacity(output.len());
        for (key, output) in output {
            let entry = Arc::new(Entry::new(&key, output));
            if &key == primary_key {
                primary_entry = Some(entry.clone());
            }
            entries.push(entry);
        }
        let primary = primary_entry.expect("primary key not found during construction of tag\nthis is a bug!\nplease report it: https://github.com/chanced/navajo/issues/new");
        Self {
            entries,
            primary,
            truncate_to: None,
            omit_header: false,
        }
    }

    pub(super) fn keys(&self) -> impl Iterator<Item = &Key<Material>> {
        self.entries.iter().map(|e| &e.key)
    }
}

#[derive(Clone)]
struct Entry {
    key: Key<Material>,
    truncate_to: Option<usize>,
    output: Output,
}

impl Entry {
    pub(super) fn new(key: &Key<Material>, output: Output) -> Self {
        Self {
            key: key.clone(),
            output,
            truncate_to: None,
        }
    }
    pub(super) fn truncate(&self, len: usize) -> Result<Self, TruncationError> {
        if !self.truncatable() {
            return Err(TruncationError::NotTruncatable);
        }
        if len >= self.key.algorithm().tag_len() {
            return Err(TruncationError::TooLong);
        }
        Ok(Self {
            key: self.key.clone(),
            truncate_to: Some(len),
            output: self.output.clone(),
        })
    }
    pub fn verify(&self, tag: &[u8]) -> Result<(), MacVerificationError> {
        let output = self
            .truncate_to
            .map(|len| &self.output.as_ref()[..len])
            .unwrap_or(self.output.as_ref());
        let header = self.key.material().prefix.as_deref().unwrap_or(&[]);

        if tag.len() != output.len() + header.len() {
            return verify_slices_are_equal(tag, output).map_err(|_| MacVerificationError);
        }

        if verify_slices_are_equal(&tag[..header.len()], &output[..header.len()]).is_err() {
            _ = verify_slices_are_equal(&tag[header.len()..], &output[header.len()..]);
            Err(MacVerificationError)
        } else {
            verify_slices_are_equal(&tag[header.len()..], &output[header.len()..])
                .map_err(|_| MacVerificationError)
        }
    }
    pub(super) fn truncatable(&self) -> bool {
        self.output.truncatable()
    }
}

impl AsRef<[u8]> for Entry {
    fn as_ref(&self) -> &[u8] {
        self.output.as_ref()
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
