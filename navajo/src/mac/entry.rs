use alloc::vec::Vec;

use crate::{constant_time::verify_slices_are_equal, error::MacVerificationError};

use super::output::{DigestOutput, Output};

#[derive(Clone, Debug)]
pub(super) struct Entry {
    key_id: u32,
    is_primary: bool,
    header: Vec<u8>,
    output: Output,
}

impl Entry {
    pub(super) fn new(key_id: u32, is_primary: bool, header: Vec<u8>, output: Output) -> Self {
        Self {
            key_id,
            is_primary,
            header,
            output,
        }
    }

    pub(super) fn key_id(&self) -> u32 {
        self.key_id
    }
    pub(super) fn is_primary(&self) -> bool {
        self.is_primary
    }
    pub(super) fn header(&self) -> &[u8] {
        &self.header
    }

    pub(super) fn verify(
        &self,
        other: &[u8],
        truncate_to: Option<usize>,
    ) -> Result<(), MacVerificationError> {
        let header = self.header();
        let tag = self.output_bytes();

        let o_len = other.len();
        let trunc = truncate_to.unwrap_or(0);
        let h_len = header.len();
        let t_len = tag.len();

        if o_len < 8 || o_len < trunc || t_len + h_len < o_len {
            return Err(MacVerificationError);
        }
        let eq = verify_slices_are_equal;

        // checking if tag with its header equals other
        if t_len + h_len == o_len
            && eq(header, &other[..h_len]).is_ok()
            && eq(tag, &other[h_len..]).is_ok()
        {
            return Ok(());
        }

        // checking if tag without its header equals other
        if eq(tag, other).is_ok() {
            return Ok(());
        }

        // checking if tag truncated equals other
        if trunc == o_len && eq(&tag[..trunc], other).is_ok() {
            return Ok(());
        }

        // checking if tag truncated with its header equals other
        if o_len > h_len
            && trunc == o_len
            && eq(header, &other[..h_len]).is_ok()
            && eq(&tag[..(trunc - h_len)], &other[h_len..trunc]).is_ok()
        {
            return Ok(());
        }
        Err(MacVerificationError)
    }
    pub(super) fn output_bytes(&self) -> &[u8] {
        self.output.as_bytes()
    }
    pub(super) fn output(&self) -> &Output {
        &self.output
    }

    pub(super) fn truncatable(&self) -> bool {
        self.output.truncatable()
    }
}

#[cfg(feature = "blake3")]
#[cfg(test)]
mod tests {

    use crate::SystemRandom;

    use super::Output;
    use super::*;
    #[test]
    fn test_verify_blake3() {
        let rand = SystemRandom;
        let mut hash_arr = [0; 32];
        let id = crate::keyring::gen_id(&rand);
        let id_bytes = id.to_be_bytes();
        rand.fill(&mut hash_arr);
        let hash = blake3::Hash::from(hash_arr);
        let output = Output::Blake3(crate::mac::output::Blake3Output::from(hash));
        let entry = Entry::new(id, true, id_bytes.to_vec(), output);

        let tag_with_header = [&id_bytes[..], &hash_arr[..]].concat();
        assert!(entry.verify(&hash_arr, None).is_ok());
        assert!(entry.verify(&tag_with_header, None).is_ok());
        let truncated = &hash_arr[..16];
        assert!(entry.verify(truncated, Some(16)).is_ok());
        let truncated_with_header = [&id_bytes[..], &hash_arr[..12]].concat();
        assert!(entry.verify(&truncated_with_header, Some(16)).is_ok());
    }
}
