// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Nirapod Labs

//! The bag of cells: the serialized form of a cell graph.
//!
//! The read path and the write path each take a child module: [`parse`] reads a bag's
//! cells once [`header`] has checked its header, and [`serialize`] writes one. The parts
//! they share, the magic, the bounds, the checksum, the byte reader, and the header those
//! reads fill, stay here where both paths and the [`view`] over a bag reach them.

use crate::error::CellError;

mod header;
mod parse;
mod serialize;
mod view;

#[cfg(feature = "compress")]
pub mod compress;

pub use parse::parse_boc;
pub use serialize::{file_hash, serialize_boc, serialize_boc_with, BocOptions};
pub use view::BocView;

// The read path is spread across the header and parse children and the view over it, so the
// entry points those children share are named here for them to reach through the parent.
use header::read_header;
use parse::{read_and_build, verify_roots};

/// The four bytes every bag of cells begins with.
const MAGIC: [u8; 4] = [0xb5, 0xee, 0x9c, 0x72];

/// The most cells [`parse_boc`] will read from one bag.
///
/// A bag arrives from a liteserver, which is not trusted, so a declared cell count is
/// checked against this before anything is allocated for it.
///
/// The number comes from what a cell costs rather than from what the format allows. A
/// parsed cell is about 250 bytes of live heap and the smallest one on the wire is two,
/// so without a bound of this shape a bag expands by two orders of magnitude on the way
/// in. Real proofs run 35 to 58 wire bytes per cell, which leaves this three orders of
/// magnitude above anything the chain produces.
pub const MAX_CELLS: usize = 1 << 17;

/// The longest chain of references [`parse_boc`] will read.
///
/// Bounding the depth keeps a deep graph from overflowing the stack when the cells are
/// later walked or dropped.
pub const MAX_DEPTH: usize = 1024;

/// The CRC-32C (Castagnoli) checksum a bag of cells may carry, reflected form.
fn crc32c(bytes: &[u8]) -> u32 {
    let mut crc = 0xFFFF_FFFFu32;
    for &byte in bytes {
        crc ^= u32::from(byte);
        for _ in 0..8 {
            crc = if crc & 1 != 0 {
                (crc >> 1) ^ 0x82F6_3B78
            } else {
                crc >> 1
            };
        }
    }
    !crc
}

/// A reader that returns an error rather than reading past the end.
struct Reader<'a> {
    bytes: &'a [u8],
    at: usize,
}

impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8], CellError> {
        let end = self.at.checked_add(n).ok_or(CellError::Truncated)?;
        let out = self.bytes.get(self.at..end).ok_or(CellError::Truncated)?;
        self.at = end;
        Ok(out)
    }

    fn byte(&mut self) -> Result<u8, CellError> {
        self.take(1)?.first().copied().ok_or(CellError::Truncated)
    }

    fn uint(&mut self, n: usize) -> Result<u64, CellError> {
        Ok(self
            .take(n)?
            .iter()
            .fold(0u64, |value, &b| (value << 8) | u64::from(b)))
    }

    fn remaining(&self) -> usize {
        self.bytes.len() - self.at
    }

    fn consumed(&self) -> usize {
        self.at
    }
}

/// The number of data bits a cell holds, from its bit descriptor and stored bytes.
///
/// An odd descriptor means the final byte is partial: it carries the data bits, then a
/// set bit, then zeros.
///
/// Visible to the crate so the encoding-uniqueness property can reach it. A cell's
/// second encoding exists only at this level: the serializer never writes one, so a
/// property that goes out through [`serialize_boc`] cannot construct the case at all.
pub fn bit_len(d2: u8, data: &[u8]) -> Result<u16, CellError> {
    let full = u16::from(d2 >> 1);
    if d2 & 1 == 0 {
        return Ok(full * 8);
    }
    let last = *data
        .last()
        .ok_or(CellError::Malformed("partial byte with no data"))?;
    // Both bytes that carry no data, 0x00 and 0x80, are refused. A 0x80 tail describes a
    // byte-aligned cell the long way round, and accepting it would leave a byte of pure
    // padding inside `data` for the hash to cover, so this crate and TON would disagree
    // about the identity of a cell they both accepted.
    if last.trailing_zeros() >= 7 {
        return Err(CellError::Malformed("partial byte has no completion bit"));
    }
    #[allow(
        clippy::cast_possible_truncation,
        reason = "last is a u8, so trailing_zeros is at most 8, which fits u16"
    )]
    let low_zeros = last.trailing_zeros() as u16;
    Ok(full * 8 + (7 - low_zeros))
}

/// A bag's header: the counts and flags read before the cells, and where the cells begin.
///
/// [`read_header`] fills one and leaves the reader at the first cell, so the cells can be
/// read against counts already held to the bytes, or left unread while the header alone is
/// inspected through a [`BocView`].
struct Header {
    /// The total number of cells the bag carries.
    count: usize,
    /// The number of bytes a reference index takes.
    ref_size: usize,
    /// The positions of the root cells among the count.
    root_list: Vec<usize>,
    /// Whether the bag carries a per-cell offset index.
    has_index: bool,
    /// Whether the bag ends in a CRC-32C checksum.
    has_checksum: bool,
    /// The number of bytes the cells themselves take.
    cell_area: usize,
    /// Where the cells begin, past the header, the roots and the index.
    body_offset: usize,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cell::CellType;
    use sha2::{Digest, Sha256};

    // One cell of eight bits holding 0xab.
    const ONE_CELL: [u8; 14] = [
        0xb5, 0xee, 0x9c, 0x72, 0x01, 0x01, 0x01, 0x01, 0x00, 0x03, 0x00, 0x00, 0x02, 0xab,
    ];

    // A root with one reference; the referenced cell holds 0xcd.
    const TWO_CELLS: [u8; 17] = [
        0xb5, 0xee, 0x9c, 0x72, 0x01, 0x01, 0x02, 0x01, 0x00, 0x06, 0x00, 0x01, 0x00, 0x01, 0x00,
        0x02, 0xcd,
    ];

    #[test]
    fn parses_a_single_cell() {
        let roots = parse_boc(&ONE_CELL).unwrap();
        assert_eq!(roots.len(), 1);
        assert_eq!(roots[0].bit_len(), 8);
        assert_eq!(roots[0].data(), &[0xab]);
        assert_eq!(roots[0].cell_type(), CellType::Ordinary);
        assert_eq!(roots[0].level_mask(), 0);
        assert!(roots[0].refs().is_empty());
    }

    #[test]
    fn parses_a_reference() {
        let roots = parse_boc(&TWO_CELLS).unwrap();
        assert_eq!(roots[0].refs().len(), 1);
        assert_eq!(roots[0].refs()[0].data(), &[0xcd]);
        assert_eq!(roots[0].reference(0).unwrap().bit_len(), 8);
        assert!(roots[0].reference(1).is_none());
    }

    #[test]
    fn rejects_bytes_that_are_not_a_bag_of_cells() {
        assert_eq!(
            parse_boc(&[0, 1, 2, 3, 4, 5]),
            Err(CellError::NotABagOfCells)
        );
        assert_eq!(parse_boc(&[]), Err(CellError::Truncated));
    }

    #[test]
    fn rejects_a_truncated_bag() {
        for cut in 4..ONE_CELL.len() {
            assert!(
                parse_boc(&ONE_CELL[..cut]).is_err(),
                "a bag cut to {cut} bytes must not parse"
            );
        }
    }

    #[test]
    fn rejects_a_reference_out_of_range() {
        let bag = [
            0xb5, 0xee, 0x9c, 0x72, 0x01, 0x01, 0x01, 0x01, 0x00, 0x03, 0x00, 0x01, 0x00, 0x05,
        ];
        assert_eq!(parse_boc(&bag), Err(CellError::BadReference));
    }

    #[test]
    fn rejects_a_reference_that_does_not_point_forward() {
        // A cell referencing itself would be a cycle.
        let bag = [
            0xb5, 0xee, 0x9c, 0x72, 0x01, 0x01, 0x01, 0x01, 0x00, 0x03, 0x00, 0x01, 0x00, 0x00,
        ];
        assert_eq!(parse_boc(&bag), Err(CellError::BadReference));
    }

    #[test]
    fn rejects_a_cell_count_past_the_limit_before_allocating() {
        // Four-byte reference indices and a count of 0xffffffff.
        let bag = [
            0xb5, 0xee, 0x9c, 0x72, 0x04, 0x01, 0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x01,
            0x00, 0x00, 0x00, 0x00, 0x00,
        ];
        assert_eq!(
            parse_boc(&bag),
            Err(CellError::TooManyCells { limit: MAX_CELLS })
        );
    }

    #[test]
    fn rejects_a_cell_count_the_bytes_cannot_hold() {
        // Two hundred cells declared, no cell data at all.
        let bag = [
            0xb5, 0xee, 0x9c, 0x72, 0x01, 0x01, 0xc8, 0x01, 0x00, 0x03, 0x00,
        ];
        assert_eq!(parse_boc(&bag), Err(CellError::Truncated));
    }

    #[test]
    fn rejects_bad_header_sizes() {
        // A reference size of zero.
        let bag = [0xb5, 0xee, 0x9c, 0x72, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00];
        assert_eq!(parse_boc(&bag), Err(CellError::Header("reference size")));
        // An offset size of zero.
        let bag = [0xb5, 0xee, 0x9c, 0x72, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00];
        assert_eq!(parse_boc(&bag), Err(CellError::Header("offset size")));
    }

    #[test]
    fn rejects_a_root_count_of_zero() {
        let bag = [
            0xb5, 0xee, 0x9c, 0x72, 0x01, 0x01, 0x01, 0x00, 0x00, 0x03, 0x00, 0x00, 0x02, 0xab,
        ];
        assert_eq!(parse_boc(&bag), Err(CellError::Header("root count")));
    }

    #[test]
    fn rejects_an_unknown_exotic_type() {
        // The exotic flag is set and the leading data byte names no kind.
        let bag = [
            0xb5, 0xee, 0x9c, 0x72, 0x01, 0x01, 0x01, 0x01, 0x00, 0x03, 0x00, 0x08, 0x02, 0x7f,
        ];
        assert_eq!(
            parse_boc(&bag),
            Err(CellError::Malformed("unknown exotic cell type"))
        );
    }

    #[test]
    fn rejects_a_pruned_branch_whose_length_disagrees_with_its_mask() {
        // Exotic, pruned, a mask marking one level, but no room for a hash and depth.
        let bag = [
            0xb5, 0xee, 0x9c, 0x72, 0x01, 0x01, 0x01, 0x01, 0x00, 0x04, 0x00, 0x28, 0x04, 0x01,
            0x01,
        ];
        assert_eq!(
            parse_boc(&bag),
            Err(CellError::Malformed(
                "pruned branch length disagrees with its level mask"
            ))
        );

        // One level's worth of hash and depth, and one byte more. A trailing byte is
        // hashed like any other, so a length that is merely sufficient would let one
        // pruned branch carry a second meaning past the reads that index it.
        let mut body = vec![0x01, 0x01];
        body.extend_from_slice(&[0x11; 32]);
        body.extend_from_slice(&[0x00, 0x01]);
        body.push(0xde);
        let mut bag = vec![0xb5, 0xee, 0x9c, 0x72, 0x01, 0x01, 0x01, 0x01, 0x00];
        #[allow(
            clippy::cast_possible_truncation,
            reason = "body is 37 bytes here, so 2 + body.len() is far under u8::MAX"
        )]
        bag.push((2 + body.len()) as u8);
        bag.push(0x00);
        bag.push(0x28);
        #[allow(
            clippy::cast_possible_truncation,
            reason = "body is 37 bytes here, so body.len() * 2 is far under u8::MAX"
        )]
        bag.push((body.len() * 2) as u8);
        bag.extend_from_slice(&body);
        assert_eq!(
            parse_boc(&bag),
            Err(CellError::Malformed(
                "pruned branch length disagrees with its level mask"
            ))
        );
    }

    #[test]
    fn a_pruned_branch_may_not_carry_references() {
        // A pruned branch answers with the hash of the subtree it replaced and never
        // hashes its own children, so one allowed to carry a child would hash the same
        // whatever hangs beneath it. Two bags differing only in that subtree would share
        // an identity, which is the one thing a cell hash exists to prevent.
        let bag = [
            0xb5, 0xee, 0x9c, 0x72, 0x01, 0x01, 0x02, 0x01, 0x00, 0x08, 0x00, // header
            0x29, 0x04, 0x01, 0x01, 0x01, // pruned, one reference, to cell 1
            0x00, 0x02, 0xab, // the cell it must not be allowed to carry
        ];
        assert_eq!(
            parse_boc(&bag),
            Err(CellError::Malformed(
                "exotic cell has the wrong number of references"
            ))
        );
    }

    #[test]
    fn a_pruned_branch_stands_in_for_something() {
        // A mask of zero stores no hash, so the cell answers every level with its own and
        // stands in for nothing. TON's builder does not produce the shape.
        let bag = [
            0xb5, 0xee, 0x9c, 0x72, 0x01, 0x01, 0x01, 0x01, 0x00, 0x04, 0x00, 0x08, 0x04, 0x01,
            0x00,
        ];
        assert_eq!(
            parse_boc(&bag),
            Err(CellError::Malformed("pruned branch has no level"))
        );
    }

    #[test]
    fn rejects_a_cell_claiming_more_references_than_the_model_allows() {
        // The field is three bits wide, so it can say five through seven. Refused before
        // the indices are read, since the count is what sizes that read.
        let bag = [
            0xb5, 0xee, 0x9c, 0x72, 0x01, 0x01, 0x01, 0x01, 0x00, 0x02, 0x00, 0x05, 0x00,
        ];
        assert_eq!(
            parse_boc(&bag),
            Err(CellError::Malformed("cell has more than four references"))
        );
    }

    #[test]
    fn reads_the_bit_length_of_a_partial_byte() {
        // Twelve bits: the byte 0x12, then four bits, a set bit, and zeros.
        assert_eq!(bit_len(0x03, &[0x12, 0xa8]).unwrap(), 12);
        // Eight bits, a whole byte.
        assert_eq!(bit_len(0x02, &[0xab]).unwrap(), 8);
        // No bits at all.
        assert_eq!(bit_len(0x00, &[]).unwrap(), 0);
        // A partial byte with no completion bit cannot be read.
        assert!(bit_len(0x01, &[0x00]).is_err());
        // Nor one whose completion bit is the only bit it has: the byte carries no data,
        // so this describes a byte-aligned cell the long way round.
        assert!(bit_len(0x03, &[0xab, 0x80]).is_err());
    }

    #[test]
    fn a_byte_aligned_cell_has_one_encoding_and_one_hash() {
        // The same eight bits written both ways. The overlong form keeps a byte of pure
        // padding in the cell's data, which this crate would hash and TON would not, so
        // the two implementations would disagree about a cell they both accepted.
        let canonical = [
            0xb5, 0xee, 0x9c, 0x72, 0x01, 0x01, 0x01, 0x01, 0x00, 0x03, 0x00, 0x00, 0x02, 0xab,
        ];
        let overlong = [
            0xb5, 0xee, 0x9c, 0x72, 0x01, 0x01, 0x01, 0x01, 0x00, 0x04, 0x00, 0x00, 0x03, 0xab,
            0x80,
        ];
        assert!(parse_boc(&canonical).is_ok());
        assert_eq!(
            parse_boc(&overlong),
            Err(CellError::Malformed("partial byte has no completion bit"))
        );
    }

    #[test]
    fn the_checksum_is_the_one_everyone_else_computes() {
        // This crate writes the checksum on the way out and checks it on the way in,
        // both through this function, so a round trip agrees with itself no matter what
        // the function computes. A bag from a reference node does not, and neither does
        // the published check value for CRC-32C, which is what this pins.
        assert_eq!(crc32c(b"123456789"), 0xE306_9283);
        assert_eq!(crc32c(b""), 0);
    }

    #[test]
    fn a_bag_whose_checksum_disagrees_is_refused() {
        let bag = serialize_boc(&parse_boc(&TWO_CELLS).unwrap()).unwrap();
        // Parsing what was just written exercises the check in the direction that
        // succeeds, which nothing else here does.
        assert_eq!(
            parse_boc(&bag).unwrap()[0].repr_hash(),
            parse_boc(&TWO_CELLS).unwrap()[0].repr_hash()
        );

        // A byte of payload altered under a checksum that still describes the original.
        let mut corrupt = bag.clone();
        let last = corrupt.len() - 5;
        corrupt[last] ^= 0xff;
        assert_eq!(parse_boc(&corrupt), Err(CellError::Checksum));

        // And the checksum itself altered under payload that is still intact.
        let mut forged = bag;
        let tail = forged.len() - 1;
        forged[tail] ^= 0xff;
        assert_eq!(parse_boc(&forged), Err(CellError::Checksum));
    }

    #[test]
    fn a_dense_bag_parses_and_an_overcounted_one_does_not() {
        // Every cell costs at least its two descriptor bytes, so a count whose minimum
        // size exceeds what is left is truncation before anything is allocated.
        //
        // The guard runs before the root list is read, so what it compares against still
        // includes those bytes. That makes its exact boundary unreachable by a bag that
        // would otherwise parse, and the off-by-one in it unobservable: a bag dense
        // enough to sit on the boundary is one the cell reader rejects anyway. What is
        // worth pinning is the pair below, a dense bag that parses and an overcounted
        // one that does not.
        //
        // Two empty cells, four payload bytes, which is exactly two apiece.
        const EXACT: [u8; 15] = [
            0xb5, 0xee, 0x9c, 0x72, // magic
            0x01, // one byte per reference, no index, no checksum
            0x01, // one byte per offset
            0x02, // two cells
            0x01, // one root
            0x00, // no absent cells
            0x04, // four bytes of cell area
            0x00, // the root is cell zero
            0x00, 0x00, // cell zero: no references, no bits
            0x00, 0x00, // cell one: the same
        ];
        assert!(parse_boc(&EXACT).is_ok(), "the boundary itself must parse");

        // One cell more than the bytes can hold.
        let mut overcount = EXACT;
        overcount[6] = 0x03;
        assert_eq!(parse_boc(&overcount), Err(CellError::Truncated));
    }

    #[test]
    fn every_option_combination_round_trips() {
        let roots = parse_boc(&TWO_CELLS).unwrap();
        let expected = *roots[0].repr_hash();
        for index in [false, true] {
            for crc32c in [false, true] {
                let bag = serialize_boc_with(&roots, &BocOptions { index, crc32c }).unwrap();
                let back = parse_boc(&bag).expect("the bag reads back");
                assert_eq!(
                    *back[0].repr_hash(),
                    expected,
                    "index={index} crc32c={crc32c}"
                );
            }
        }
    }

    #[test]
    fn the_default_serialization_is_the_plain_one() {
        // serialize_boc is serialize_boc_with under the default options, byte for byte.
        let roots = parse_boc(&TWO_CELLS).unwrap();
        assert_eq!(
            serialize_boc(&roots).unwrap(),
            serialize_boc_with(&roots, &BocOptions::default()).unwrap(),
        );
    }

    #[test]
    fn an_indexed_bag_states_where_each_cell_begins() {
        // The index adds count offsets between the roots and the cells, so the bag is longer
        // by exactly that, and still reads back to the same cells.
        let roots = parse_boc(&TWO_CELLS).unwrap();
        let plain = serialize_boc_with(
            &roots,
            &BocOptions {
                index: false,
                crc32c: true,
            },
        )
        .unwrap();
        let indexed = serialize_boc_with(
            &roots,
            &BocOptions {
                index: true,
                crc32c: true,
            },
        )
        .unwrap();
        assert!(indexed.len() > plain.len(), "the index takes room");
        assert_eq!(
            parse_boc(&indexed).unwrap()[0].repr_hash(),
            roots[0].repr_hash(),
        );
    }

    #[test]
    fn the_file_hash_is_the_sha256_of_the_bag() {
        let roots = parse_boc(&TWO_CELLS).unwrap();
        let bag = serialize_boc(&roots).unwrap();
        let expected: [u8; 32] = Sha256::digest(&bag).into();
        assert_eq!(
            file_hash(&bag),
            expected,
            "the file hash is the bag's sha256"
        );

        // A different bag names itself differently.
        let other = serialize_boc(&parse_boc(&ONE_CELL).unwrap()).unwrap();
        assert_ne!(file_hash(&bag), file_hash(&other));
    }

    #[test]
    fn a_bag_of_two_roots_reads_back_both() {
        let one = parse_boc(&ONE_CELL).unwrap().remove(0);
        let two = parse_boc(&TWO_CELLS).unwrap().remove(0);
        let bag = serialize_boc(&[one.clone(), two.clone()]).expect("two roots serialize");
        let back = parse_boc(&bag).expect("the two-root bag reads back");
        assert_eq!(back.len(), 2, "both roots come back");
        assert_eq!(back[0].repr_hash(), one.repr_hash());
        assert_eq!(back[1].repr_hash(), two.repr_hash());
    }
}
