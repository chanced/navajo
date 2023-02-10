use super::entry::Entry;
use crate::{
    constant_time::verify_slices_are_equal,
    error::{MacVerificationError, TruncationError},
    Mac,
};
use alloc::{sync::Arc, vec::Vec};
use rayon::prelude::{IntoParallelRefIterator, ParallelIterator};

/// A data structure containing a MAC tag for each key in a [`Mac`](super::Mac)
/// at the point of computation. Capable of comparing itself to other [`Tag`]s
/// or `&[u8]`.
///
/// ## Output
/// When calling [`Self::as_bytes`] or [`Self::as_ref`], the primary key's
/// output will returned. The default behavior is to return the full MAC with
/// the header prefixed. If navajo generated the key, the MAC will be in the
/// format:
///
/// ```plaintext
/// || Key ID (4 bytes) || MAC (variable length based on algorithm) ||
/// ```
///
/// ### Omitting the header
/// A call to [`Self::omit_header`] will return a [`clone`](Self::clone) of the
/// `Tag` with a flag set indicating that the header should be omitted when
/// represented as bytes. Any calls to [`Self::as_bytes`] or [`Self::as_ref`]
/// will return the MAC bytes without the header.
///
/// ### Truncation
/// To truncate the `Tag` to a specific length, a call to [`Self::truncate_to`]
/// will [`clone`](Self::clone) the `Tag` and assign the truncation size in the
/// returned `Tag`. All uses of resulting `Tag` will be truncated, which
/// includes the output (e.g. [`as_bytes`](Self::as_bytes),
/// [`as_ref`](Self::as_ref)) as well as for verification purposes.
///
/// ## Importing MAC tags
/// To compute a `Tag` to match a different library, use a [`Mac`] with the
/// provided key(s). To do so, create a new instance with
/// [`Mac::new_with_external_tag`] or add to an existing keyring with
/// [`Mac::add_external_key`]. For libraries such as
/// [Tink](https://developers.google.com/tink) that use headers, make sure to
/// include their prefix during construction by passing the `prefix` argument.
///
/// The output of external tags will be:
/// ```plaintext
/// || Prefix || MAC (variable length based on algorithm) ||
/// ```
/// The same rules apply for truncation and omitting the header (which would be
/// the Prefix for external tags).
///
#[derive(Clone, Debug)]
pub struct Tag {
    entries: Arc<Vec<Entry>>,
    primary_idx: usize,
    pub(super) primary_tag: Arc<Vec<u8>>,
    primary_tag_header_len: usize,
    truncate_to: Option<usize>,
    /// If true, the header will be omitted from the output of `as_bytes` and
    /// `as_ref`.
    omit_header: bool,
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
    pub fn update(&mut self, mac: &Mac) {
        todo!()
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
    pub(super) fn tag_count(&self) -> usize {
        self.entries.len()
    }
    fn eq_slice(&self, other: &[u8]) -> Result<(), MacVerificationError> {
        if other.len() == self.primary_tag.len()
            && verify_slices_are_equal(self.primary_tag.as_ref(), other).is_ok()
        {
            return Ok(());
        }
        for entry in self.entries.iter() {
            if entry.verify(other, self.truncate_to).is_ok() {
                return Ok(());
            }
        }
        Err(MacVerificationError)
    }
    fn eq_tag(&self, other: &Tag) -> Result<(), MacVerificationError> {
        if self.entries.len() > 1 {
            if other.entries.len() > 1 {
                self.entries
                    .par_iter()
                    .find_any(|entry| {
                        other
                            .entries
                            .par_iter()
                            .find_any(|other_entry| {
                                entry
                                    .verify(other_entry.output_bytes(), self.truncate_to)
                                    .is_ok()
                            })
                            .is_some()
                    })
                    .map(|_| ())
                    .ok_or(MacVerificationError)
            } else {
                self.entries
                    .par_iter()
                    .find_any(|entry| {
                        entry
                            .verify(other.primary_tag.as_ref(), self.truncate_to)
                            .is_ok()
                    })
                    .map(|_| ())
                    .ok_or(MacVerificationError)
            }
        } else if other.entries.len() > 1 {
            other.eq_tag(self)
        } else {
            other.eq_slice(self.primary_tag.as_ref())
        }
    }
}

impl AsRef<[u8]> for Tag {
    fn as_ref(&self) -> &[u8] {
        self.as_bytes()
    }
}

impl PartialEq<[u8]> for Tag {
    fn eq(&self, other: &[u8]) -> bool {
        self.eq_slice(other).is_ok()
    }
}
impl PartialEq<Vec<u8>> for Tag {
    fn eq(&self, other: &Vec<u8>) -> bool {
        self.eq_slice(other.as_slice()).is_ok()
    }
}

impl PartialEq<Tag> for Tag {
    fn eq(&self, other: &Self) -> bool {
        self.eq_tag(other).is_ok()
    }
}
impl PartialEq<&Tag> for Tag {
    fn eq(&self, other: &&Self) -> bool {
        self.eq_tag(other).is_ok()
    }
}
impl PartialEq<Tag> for &Tag {
    fn eq(&self, other: &Tag) -> bool {
        other.eq_tag(self).is_ok()
    }
}

impl PartialEq<Tag> for [u8] {
    fn eq(&self, other: &Tag) -> bool {
        other.eq_slice(self).is_ok()
    }
}
impl Eq for Tag {}

#[cfg(test)]
mod tests {
    use crate::mac::output::Output;

    use super::*;

    #[test]
    fn test_verify() {
        let mut hash_arr = [0; 32];
        let id = crate::keyring::gen_id();
        let id_bytes = id.to_be_bytes();
        crate::rand::fill(&mut hash_arr);
        let hash = blake3::Hash::from(hash_arr);
        let output = Output::Blake3(crate::mac::output::Blake3Output::from(hash));
        let entry = Entry::new(id, true, id_bytes.to_vec(), output.clone());
        let tag = Tag::new(std::iter::once(entry));
        let other = tag.clone();
        assert_eq!(tag, other);

        let output_1 = output;
        let entry_1 = Entry::new(id, false, id_bytes.to_vec(), output_1);

        let id_2 = crate::keyring::gen_id();
        let id_bytes_2 = id_2.to_be_bytes();
        let mut hash_arr_2 = [0; 32];
        crate::rand::fill(&mut hash_arr_2);
        let hash_2 = blake3::Hash::from(hash_arr_2);
        let output_2 = Output::Blake3(crate::mac::output::Blake3Output::from(hash_2));
        let entry_2 = Entry::new(id, true, id_bytes_2.to_vec(), output_2.clone());
        let tag_2 = Tag::new([entry_1.clone(), entry_2].iter().cloned());

        assert_eq!(tag, tag_2);

        let entry_2 = Entry::new(id, false, id_bytes_2.to_vec(), output_2);
        let id_3 = crate::keyring::gen_id();
        let id_bytes_3 = id_3.to_be_bytes();
        let mut hash_arr_3 = [0; 32];
        crate::rand::fill(&mut hash_arr_3);
        let hash_3 = blake3::Hash::from(hash_arr_3);
        let output_3 = Output::Blake3(crate::mac::output::Blake3Output::from(hash_3));
        let entry_3 = Entry::new(id, true, id_bytes_3.to_vec(), output_3);
        let tag_3 = Tag::new([entry_1, entry_2, entry_3].iter().cloned());

        assert_eq!(tag_2, tag_3);
    }
}
