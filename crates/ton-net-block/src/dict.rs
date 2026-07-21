//! Looking one key up in a TON dictionary.
//!
//! A TON dictionary is a binary radix tree over fixed-width keys. Each edge carries a
//! label, a run of key bits shared by everything below it, so a sparse tree stays
//! shallow. This module walks that tree for a single key; it does not build or change
//! one, which is all a read client needs.
//!
//! Navigation is the same for a plain dictionary and an augmented one. An augmented
//! dictionary carries extra data after the references in a fork and before the value in
//! a leaf, and neither sits where a walk has to read it, so the caller reads the extra
//! data itself once the walk lands.

use ton_net_cell::{Cell, Slice};

use crate::error::BlockError;

/// Where a lookup landed: the cell holding the leaf, and where its contents start.
///
/// The walk stops once the key is spent, which leaves the cursor just past the label.
/// [`slice`](DictEntry::slice) reopens the cell at that point, so the caller reads
/// whatever the dictionary stores.
#[derive(Debug, Clone)]
pub struct DictEntry {
    cell: Cell,
    bit_offset: u16,
}

impl DictEntry {
    /// The cell the leaf sits in.
    #[must_use]
    pub fn cell(&self) -> &Cell {
        &self.cell
    }

    /// A cursor positioned at the leaf's contents.
    ///
    /// # Errors
    ///
    /// Returns [`BlockError::Cell`] if the cell is shorter than the walk recorded.
    pub fn slice(&self) -> Result<Slice<'_>, BlockError> {
        let mut slice = self.cell.parse();
        slice.skip_bits(usize::from(self.bit_offset))?;
        Ok(slice)
    }
}

/// The bit of `key` at `index`, counting from the most significant bit of the first byte.
fn key_bit(key: &[u8], index: usize) -> bool {
    match key.get(index / 8) {
        Some(byte) => (byte >> (7 - (index % 8))) & 1 == 1,
        None => false,
    }
}

/// The width of a `#<= max` field: enough bits to hold every value up to `max`.
fn bounded_width(max: u16) -> u32 {
    u16::BITS - max.leading_zeros()
}

/// Reads an edge label, returning the key bits it covers.
///
/// The three encodings are a unary-counted run, an explicit length, and a repeated bit.
fn read_label(slice: &mut Slice<'_>, max: u16) -> Result<Vec<bool>, BlockError> {
    if !slice.load_bit()? {
        // hml_short: a unary length, then that many bits.
        let mut len = 0u16;
        while slice.load_bit()? {
            len += 1;
            if len > max {
                return Err(BlockError::LabelTooLong);
            }
        }
        let mut bits = Vec::with_capacity(usize::from(len));
        for _ in 0..len {
            bits.push(slice.load_bit()?);
        }
        return Ok(bits);
    }

    if !slice.load_bit()? {
        // hml_long: an explicit length, then that many bits.
        let len = slice.load_uint(bounded_width(max))? as u16;
        if len > max {
            return Err(BlockError::LabelTooLong);
        }
        let mut bits = Vec::with_capacity(usize::from(len));
        for _ in 0..len {
            bits.push(slice.load_bit()?);
        }
        return Ok(bits);
    }

    // hml_same: one bit repeated a given number of times.
    let value = slice.load_bit()?;
    let len = slice.load_uint(bounded_width(max))? as u16;
    if len > max {
        return Err(BlockError::LabelTooLong);
    }
    Ok(vec![value; usize::from(len)])
}

/// Looks `key` up in the dictionary rooted at `root`.
///
/// `root` is the edge cell a `HashmapE` points at, and `key_bits` is the dictionary's
/// fixed key width. Returns `None` when the key is absent.
///
/// A walk over a Merkle proof stops at a pruned branch and returns `None`: a proof
/// covers one path and prunes the rest, so a key it does not cover is simply not there
/// to read. Telling that apart from a key genuinely absent from the full dictionary is
/// the proof engine's job, not this walk's.
///
/// # Errors
///
/// Returns [`BlockError::KeyLength`] if `key` is too short for `key_bits`, or
/// [`BlockError::Malformed`] or [`BlockError::Cell`] if the tree does not read as a
/// dictionary.
pub fn lookup(root: &Cell, key_bits: u16, key: &[u8]) -> Result<Option<DictEntry>, BlockError> {
    let needed = usize::from(key_bits).div_ceil(8);
    if key.len() < needed {
        return Err(BlockError::KeyLength {
            given: key.len() * 8,
            expected: usize::from(key_bits),
        });
    }

    let mut node = root.clone();
    let mut remaining = key_bits;
    let mut consumed = 0usize;

    loop {
        // A proof replaces the branches it does not cover with pruned placeholders,
        // which hold a hash rather than a dictionary node.
        if node.is_exotic() {
            return Ok(None);
        }

        let mut slice = node.parse();
        let label = read_label(&mut slice, remaining)?;
        if label.len() > usize::from(remaining) {
            return Err(BlockError::LabelTooLong);
        }
        for (offset, bit) in label.iter().enumerate() {
            if key_bit(key, consumed + offset) != *bit {
                return Ok(None);
            }
        }
        consumed += label.len();
        remaining -= label.len() as u16;

        if remaining == 0 {
            let bit_offset = node.bit_len() - slice.remaining_bits() as u16;
            return Ok(Some(DictEntry {
                cell: node,
                bit_offset,
            }));
        }

        // A fork: the next key bit chooses the branch.
        let branch = usize::from(key_bit(key, consumed));
        consumed += 1;
        remaining -= 1;
        let child = node
            .reference(branch)
            .ok_or(BlockError::Malformed(
                "dictionary fork without both branches",
            ))?
            .clone();
        node = child;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_bounded_width_holds_every_value_up_to_the_maximum() {
        // A 256-bit dictionary labels lengths 0..=256, which needs nine bits.
        assert_eq!(bounded_width(256), 9);
        assert_eq!(bounded_width(255), 8);
        assert_eq!(bounded_width(30), 5);
        assert_eq!(bounded_width(1), 1);
    }

    #[test]
    fn key_bits_read_most_significant_first() {
        let key = [0b1010_0000u8, 0b0000_0001];
        assert!(key_bit(&key, 0));
        assert!(!key_bit(&key, 1));
        assert!(key_bit(&key, 2));
        assert!(key_bit(&key, 15));
        // Past the end reads as zero rather than panicking.
        assert!(!key_bit(&key, 999));
    }

    #[test]
    fn a_key_shorter_than_the_dictionary_is_refused() {
        let empty = ton_net_cell::parse_boc(&[
            0xb5, 0xee, 0x9c, 0x72, 0x01, 0x01, 0x01, 0x01, 0x00, 0x02, 0x00, 0x00, 0x00,
        ])
        .unwrap();
        assert!(matches!(
            lookup(&empty[0], 256, &[0u8; 4]),
            Err(BlockError::KeyLength { .. })
        ));
    }
}
