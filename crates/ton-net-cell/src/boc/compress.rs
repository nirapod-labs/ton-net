// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Nirapod Labs

//! LZ4 compression of a serialized bag of cells.
//!
//! TON compresses a bag of cells with LZ4, and this reads and writes that form. [`compress`]
//! and [`decompress`] work on the bytes a [`serialize_boc`](super::serialize_boc) gives and a
//! [`parse_boc`](super::parse_boc) reads; [`compress_boc`] and [`decompress_boc`] do the two
//! steps at once.
//!
//! The decode side is on the untrusted boundary. A compressed bag names the length it
//! expands to, and [`decompress`] refuses a length past a hard cap before anything is
//! allocated, so a small hostile input cannot drive a large allocation. The expansion runs
//! on `lz4_flex`'s bounds-checked safe-decode path (NET-ADR-010).
//!
//! Gated behind the `compress` feature.

use lz4_flex::{compress_prepend_size, decompress_size_prepended};

use super::{parse_boc, serialize_boc};
use crate::cell::Cell;
use crate::error::CellError;

/// The most bytes a compressed bag is allowed to expand to.
///
/// A bag larger than this could not parse anyway: [`parse_boc`](super::parse_boc) refuses
/// more than [`MAX_CELLS`](super::MAX_CELLS) cells, and every cell costs at least a couple of
/// bytes on the wire, so this sits well above what the largest readable bag needs while
/// staying a bound. It is what a decompressor may allocate before that cell-count check runs.
const MAX_DECOMPRESSED: usize = 64 << 20;

/// Compresses a serialized bag of cells with LZ4.
///
/// The output is the LZ4 block form with the original length prepended, the form
/// [`decompress`] reads back. The input is the bytes a
/// [`serialize_boc`](super::serialize_boc) gives; [`compress_boc`] pairs the two.
#[must_use]
pub fn compress(bag: &[u8]) -> Vec<u8> {
    compress_prepend_size(bag)
}

/// Decompresses an LZ4-compressed bag, refusing one that would expand past the cap.
///
/// The compressed form names the length it expands to. That length is checked against a
/// hard cap before the decoder allocates, so a small input cannot name a large allocation,
/// and the expansion itself runs on the bounds-checked decode path.
///
/// # Errors
///
/// Returns [`CellError::Truncated`] if the bytes are too short to name a length, or
/// [`CellError::Malformed`] if they name a length past the cap, or are not valid LZ4, or do
/// not expand to the length they name.
pub fn decompress(bytes: &[u8]) -> Result<Vec<u8>, CellError> {
    // lz4_flex prepends the uncompressed length as four little-endian bytes. Reading it and
    // refusing a length past the cap here is what keeps the decoder below from allocating for
    // a size a hostile input chose.
    let prefix = bytes.get(..4).ok_or(CellError::Truncated)?;
    let named = u32::from_le_bytes(prefix.try_into().map_err(|_| CellError::Truncated)?);
    let Ok(named) = usize::try_from(named) else {
        return Err(CellError::Malformed(
            "compressed bag names an impossible size",
        ));
    };
    if named > MAX_DECOMPRESSED {
        return Err(CellError::Malformed("compressed bag expands past the cap"));
    }
    decompress_size_prepended(bytes).map_err(|_| CellError::Malformed("bytes are not valid lz4"))
}

/// Compresses the bag [`serialize_boc`](super::serialize_boc) would write for `roots`.
///
/// # Errors
///
/// As [`serialize_boc`](super::serialize_boc).
pub fn compress_boc(roots: &[Cell]) -> Result<Vec<u8>, CellError> {
    Ok(compress(&serialize_boc(roots)?))
}

/// Decompresses and parses a compressed bag into its root cells.
///
/// # Errors
///
/// As [`decompress`] for the expansion, then as [`parse_boc`](super::parse_boc) for the bag
/// it uncovers.
pub fn decompress_boc(bytes: &[u8]) -> Result<Vec<Cell>, CellError> {
    parse_boc(&decompress(bytes)?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Builder;

    /// A two-cell bag: a root byte over one child byte.
    fn roots() -> Vec<Cell> {
        let mut child = Builder::new();
        child.store_uint(0xcd, 8).expect("a byte fits");
        let mut root = Builder::new();
        root.store_uint(0xab, 8).expect("a byte fits");
        root.store_ref(child.build().expect("a child forms"))
            .expect("a reference fits");
        vec![root.build().expect("a root forms")]
    }

    #[test]
    fn a_compressed_bag_round_trips() {
        let roots = roots();
        let compressed = compress_boc(&roots).expect("compresses");
        let back = decompress_boc(&compressed).expect("decompresses and parses");
        assert_eq!(back.len(), roots.len());
        assert_eq!(back[0].repr_hash(), roots[0].repr_hash());
        assert_eq!(
            back[0].reference(0).unwrap().repr_hash(),
            roots[0].reference(0).unwrap().repr_hash(),
        );
    }

    #[test]
    fn compress_and_decompress_are_inverse_on_bytes() {
        let bag = serialize_boc(&roots()).expect("serializes");
        assert_eq!(decompress(&compress(&bag)).expect("round trips"), bag);
    }

    #[test]
    fn a_bag_naming_a_size_past_the_cap_is_refused_before_allocating() {
        // A valid compressed buffer with its length prefix overwritten to name more than the
        // cap. decompress must refuse it on the prefix, before the decoder allocates.
        let mut forged = compress(&serialize_boc(&roots()).unwrap());
        let over = u32::try_from(MAX_DECOMPRESSED + 1).unwrap();
        forged[..4].copy_from_slice(&over.to_le_bytes());
        assert_eq!(
            decompress(&forged),
            Err(CellError::Malformed("compressed bag expands past the cap")),
        );
    }

    #[test]
    fn bytes_that_are_not_lz4_are_refused() {
        // A sane length prefix, then a body that is not valid LZ4.
        let mut junk = 4u32.to_le_bytes().to_vec();
        junk.extend_from_slice(&[0xff, 0xff, 0xff, 0xff]);
        assert_eq!(
            decompress(&junk),
            Err(CellError::Malformed("bytes are not valid lz4")),
        );
        // And bytes too short to even name a length.
        assert_eq!(decompress(&[0x00, 0x01]), Err(CellError::Truncated));
    }
}
