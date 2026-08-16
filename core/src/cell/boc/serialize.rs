// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Nirapod Labs

//! Writing a cell graph out as a bag of cells.

use std::collections::{HashMap, HashSet};

use sha2::{Digest, Sha256};

use super::{crc32c, MAGIC, MAX_CELLS, WITH_HASHES};
use crate::cell::cell::Cell;
use crate::cell::error::CellError;

/// The number of bytes needed to hold `value`, at least one.
pub(super) fn byte_width(value: u64) -> usize {
    let bits = u64::BITS - value.leading_zeros();
    (bits.div_ceil(8)).max(1) as usize
}

/// Appends the low `width` bytes of `value`, big-endian.
///
/// A width past the eight bytes a `u64` holds asks for a number wider than the value,
/// which no caller here does; writing all eight is what keeps this total.
pub(super) fn push_be(out: &mut Vec<u8>, value: u64, width: usize) {
    let bytes = value.to_be_bytes();
    out.extend(bytes.into_iter().skip(bytes.len().saturating_sub(width)));
}

/// Orders every cell reachable from `roots` so each comes before the cells it
/// references, which is the order a bag of cells stores them in.
///
/// Cells are shared by representation hash, so a subtree reached by two parents is
/// stored once. Reverse post-order depth-first search gives the ordering, and the walk
/// is iterative so a deep graph cannot overflow the stack.
pub(super) fn topological(roots: &[Cell]) -> Result<(Vec<Cell>, Vec<Vec<usize>>), CellError> {
    enum Step {
        Visit(Cell),
        Emit(Cell),
    }

    let mut seen: HashSet<[u8; 32]> = HashSet::new();
    let mut order: Vec<Cell> = Vec::new();
    let mut stack: Vec<Step> = roots.iter().rev().map(|c| Step::Visit(c.clone())).collect();

    while let Some(step) = stack.pop() {
        match step {
            Step::Visit(cell) => {
                if !seen.insert(*cell.repr_hash()) {
                    continue;
                }
                stack.push(Step::Emit(cell.clone()));
                for child in cell.refs().iter().rev() {
                    stack.push(Step::Visit(child.clone()));
                }
            }
            Step::Emit(cell) => order.push(cell),
        }
    }
    order.reverse();

    let index_of = index_of(&order);
    let mut children = Vec::with_capacity(order.len());
    for cell in &order {
        let mut indices = Vec::with_capacity(cell.refs().len());
        for child in cell.refs() {
            indices.push(
                index_of
                    .get(child.repr_hash())
                    .copied()
                    .ok_or(CellError::Malformed("a reference was not reachable"))?,
            );
        }
        children.push(indices);
    }
    Ok((order, children))
}

/// Maps each cell's identity to its position.
pub(super) fn index_of(order: &[Cell]) -> HashMap<[u8; 32], usize> {
    order
        .iter()
        .enumerate()
        .map(|(index, cell)| (*cell.repr_hash(), index))
        .collect()
}

/// What to write into a bag of cells beyond the cells themselves.
///
/// The format carries three optional pieces. An index gives the offset of each cell so a
/// reader can reach one without walking the bag; a CRC-32C checksum trails the whole bag so
/// a reader can refuse corrupted bytes before building anything; and each cell may state its
/// own hashes and depths ahead of its data. None of them changes which cells the bag holds,
/// only how a reader may work over it.
///
/// The type is `non_exhaustive` because its fields are public and a caller reads them, so a
/// fourth option later would otherwise be a breaking change for a caller who spelled a struct
/// literal. Reach a value through [`BocOptions::default`] and the setters beside it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct BocOptions {
    /// Write the per-cell offset index.
    pub index: bool,
    /// Write the trailing CRC-32C checksum.
    pub crc32c: bool,
    /// Write each cell's own hashes and depths ahead of its data.
    pub stored_hashes: bool,
}

impl Default for BocOptions {
    /// A checksum, no index and no stored hashes, the form [`serialize_boc`] writes.
    fn default() -> Self {
        Self {
            index: false,
            crc32c: true,
            stored_hashes: false,
        }
    }
}

impl BocOptions {
    /// Writes the per-cell offset index.
    #[must_use]
    pub fn with_index(mut self, index: bool) -> Self {
        self.index = index;
        self
    }

    /// Writes the trailing CRC-32C checksum.
    #[must_use]
    pub fn with_checksum(mut self, crc32c: bool) -> Self {
        self.crc32c = crc32c;
        self
    }

    /// Writes each cell's own hashes and depths ahead of its data.
    ///
    /// This crate's parser recomputes each cell's hashes and refuses a stored copy that
    /// disagrees, so the run buys its reader nothing. A whole block uses this form on some of
    /// its cells, 44 of the 1428 in the two block fixtures; this writes it on every cell.
    ///
    /// Off by default, because it makes a bag larger by one hash and one depth per level each
    /// cell's mask makes significant and one of each besides.
    #[must_use]
    pub fn with_stored_hashes(mut self, stored_hashes: bool) -> Self {
        self.stored_hashes = stored_hashes;
        self
    }
}

/// Serializes a cell graph as a bag of cells, with a checksum.
///
/// A cell shared by more than one parent is stored once, keyed by its representation
/// hash, so the output is as compact as the format allows.
///
/// The result is a valid bag of cells but not a canonical one: the format admits several
/// encodings of the same graph, so a round trip is measured by the cell hashes it
/// reproduces, not by byte equality with the input.
///
/// # Errors
///
/// Returns [`CellError::Header`] if `roots` is empty, or [`CellError::TooManyCells`] if
/// the graph is larger than [`MAX_CELLS`](super::MAX_CELLS).
///
/// # Examples
///
/// ```
/// use ton_net::cell::{parse_boc, serialize_boc};
///
/// let bytes = [0xb5, 0xee, 0x9c, 0x72, 0x01, 0x01, 0x01, 0x01, 0x00, 0x03, 0x00,
///              0x00, 0x02, 0xab];
/// let roots = parse_boc(&bytes)?;
/// let again = parse_boc(&serialize_boc(&roots)?)?;
/// assert_eq!(roots[0].hash(), again[0].hash());
/// # Ok::<(), ton_net::cell::CellError>(())
/// ```
pub fn serialize_boc(roots: &[Cell]) -> Result<Vec<u8>, CellError> {
    serialize_boc_with(roots, &BocOptions::default())
}

/// Serializes a cell graph as a bag of cells, choosing what to write beyond the cells.
///
/// This is [`serialize_boc`] with what is written beyond the cells under the caller's
/// control. A bag with an index states where each cell begins, and a bag with a checksum
/// can be refused on the way back in if it is corrupt. Multiple roots are written by
/// passing more than one: the shared cells beneath them are still stored once.
///
/// # Errors
///
/// As [`serialize_boc`].
pub fn serialize_boc_with(roots: &[Cell], options: &BocOptions) -> Result<Vec<u8>, CellError> {
    if roots.is_empty() {
        return Err(CellError::Header("root count"));
    }
    let (order, children) = topological(roots)?;
    let count = order.len();
    if count > MAX_CELLS {
        return Err(CellError::TooManyCells { limit: MAX_CELLS });
    }
    let positions = index_of(&order);
    let ref_size = byte_width(count as u64);

    // Each cell's end offset in the body is recorded as the body grows, which is what the
    // index writes below and what lets a reader reach a cell without walking to it.
    let mut body = Vec::new();
    let mut offsets = Vec::with_capacity(count);
    for (cell, refs) in order.iter().zip(&children) {
        let (d1, d2) = cell.stored_descriptors();
        body.push(if options.stored_hashes {
            d1 | WITH_HASHES
        } else {
            d1
        });
        body.push(d2);
        if options.stored_hashes {
            cell.identity().write_stored(&mut body);
        }
        body.extend_from_slice(cell.data());
        for &index in refs {
            push_be(&mut body, index as u64, ref_size);
        }
        offsets.push(body.len());
    }
    let offset_size = byte_width(body.len() as u64);

    let mut out = Vec::with_capacity(body.len() + 32);
    out.extend_from_slice(&MAGIC);
    // The flags byte carries the index and checksum choices in its top two bits and the
    // reference size in its low three. byte_width returns a byte count from 1 to 8, which
    // fits u8 in both pushes below.
    #[allow(
        clippy::cast_possible_truncation,
        reason = "byte_width returns 1 to 8, which fits u8"
    )]
    let mut flags = ref_size as u8;
    if options.index {
        flags |= 0x80;
    }
    if options.crc32c {
        flags |= 0x40;
    }
    out.push(flags);
    #[allow(
        clippy::cast_possible_truncation,
        reason = "byte_width returns 1 to 8, which fits u8"
    )]
    out.push(offset_size as u8);
    push_be(&mut out, count as u64, ref_size);
    push_be(&mut out, roots.len() as u64, ref_size);
    push_be(&mut out, 0, ref_size); // no absent cells
    push_be(&mut out, body.len() as u64, offset_size);
    for root in roots {
        let index = positions
            .get(root.repr_hash())
            .copied()
            .ok_or(CellError::Malformed("a root was not reachable"))?;
        push_be(&mut out, index as u64, ref_size);
    }
    // The index sits between the roots and the cells, so the cell-area size the header
    // states covers the cells alone, exactly as the reader accounts for it.
    if options.index {
        for &offset in &offsets {
            push_be(&mut out, offset as u64, offset_size);
        }
    }
    out.extend_from_slice(&body);

    if options.crc32c {
        let checksum = crc32c(&out);
        out.extend_from_slice(&checksum.to_le_bytes());
    }
    Ok(out)
}

/// The SHA-256 of a serialized bag, the hash a block or state is named by.
///
/// TON identifies a block by the pair of hashes of its two serialized bags, the root hash
/// of the block cell and this file hash of the bytes that carry it. This computes the
/// second over whatever bag is passed, which a caller pairs with the root hash a reader
/// gives to name what it just read.
#[must_use]
pub fn file_hash(bag: &[u8]) -> [u8; 32] {
    Sha256::digest(bag).into()
}
