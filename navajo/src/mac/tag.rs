use super::{entry::Entry, material::Material};

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
#[derive(Clone, Debug)]
pub struct Tag {
    entries: Arc<Vec<Entry>>,
    primary_idx: usize,
    primary_tag: Arc<Vec<u8>>,
    primary_tag_header_len: usize,
    truncate_to: Option<usize>,
    /// If true, the header will be omitted from the output of `as_bytes` and
    /// `as_ref`.
    pub omit_header: bool,
}

impl Tag {
    // fn verify_slice(&self, tag: &[u8]) -> Result<(), MacVerificationError> {
    //     if tag.len() < 8 {
    //         return Err(MacVerificationError);
    //     }
    //     if self.entries.len() == 1 {
    //     } else {
    //     }
    // }
    /// Returns this [`Tag`] cloned without truncation.
    pub fn remove_truncation(&self) -> Self {
        Self {
            omit_header: self.omit_header,
            entries: self.entries.clone(),
            truncate_to: None,
            primary_idx: self.primary_idx,
            primary_tag_header_len: self.primary_tag_header_len,
            primary_tag: self.primary_tag.clone(),
        }
    }

    /// Returns this a clone of this `Tag` with a flag set indicating that the
    /// header should be omitted when represented as bytes. Any calls to `as_bytes`
    /// or `as_ref` will return the MAC bytes without the header.
    pub fn omit_header(&self) -> Self {
        Self {
            omit_header: true,
            entries: self.entries.clone(),
            truncate_to: self.truncate_to,
            primary_idx: self.primary_idx,
            primary_tag: self.primary_tag.clone(),
            primary_tag_header_len: self.primary_tag_header_len,
        }
    }

    pub fn include_header(&self) -> Self {
        Self {
            omit_header: false,
            entries: self.entries.clone(),
            truncate_to: self.truncate_to,
            primary_idx: self.primary_idx,
            primary_tag: self.primary_tag.clone(),
            primary_tag_header_len: self.primary_tag_header_len,
        }
    }
    /// Returns this `Tag` cloned with truncation to `len` bytes if possible.
    ///
    /// Note that the truncation will be applied to entire output. The header of
    /// the `Tag` is 4 bytes. Unless the header is to be omitted (by calling
    /// [`omit_header`]), the bare minimum the `Tag` must be is 12 bytes. If the
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
        if !self.omit_header && len < 12 {
            return Err(TruncationError::TooShort);
        }
        Ok(Self {
            omit_header: self.omit_header,
            truncate_to: Some(len),
            entries: self.entries.clone(),
            primary_idx: self.primary_idx,
            primary_tag: self.primary_tag.clone(),
            primary_tag_header_len: self.primary_tag_header_len,
        })
    }
    pub fn as_bytes(&self) -> &[u8] {
        let slice = if self.omit_header {
            &self.primary_tag[self.primary_tag_header_len..]
        } else {
            &self.primary_tag
        };
        if let Some(truncate_to) = self.truncate_to {
            &slice[..truncate_to]
        } else {
            slice
        }
    }

    pub(super) fn new(entries_iter: impl Iterator<Item = Entry>) -> Self {
        let mut primary: Option<usize> = None;
        let mut entries = Vec::with_capacity(entries_iter.size_hint().1.unwrap_or(1));
        for (i, entry) in entries_iter.enumerate() {
            if entry.is_primary() {
                primary = Some(i);
            }
            entries.push(entry);
        }
        let primary_idx = primary.unwrap_or(entries.len() - 1);
        let primary = &entries[primary_idx];
        let primary_tag = Arc::new([primary.header(), primary.output_bytes()].concat());
        let primary_tag_header_len = primary.header().len();
        Self {
            entries: Arc::new(entries),
            primary_idx,
            primary_tag,
            primary_tag_header_len,
            truncate_to: None,
            omit_header: false,
        }
    }

    fn eq_slice(&self, other: &[u8]) -> Result<(), MacVerificationError> {
        if other.len() < 8 {
            return Err(MacVerificationError);
        }
        if verify_slices_are_equal(self.as_bytes(), other).is_ok() {
            return Ok(());
        }
        for entry in self.entries.iter() {
            if entry.verify(other, self.truncate_to).is_ok() {
                return Ok(());
            }
        }

        todo!()
    }
}

impl PartialEq for Tag {
    fn eq(&self, other: &Self) -> bool {
        self.as_bytes() == other.as_bytes()
    }
}

impl AsRef<[u8]> for Tag {
    fn as_ref(&self) -> &[u8] {
        self.as_bytes()
    }
}
