// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Nirapod Labs

//! Writing a bag of cells in pieces, without holding the whole of it at once.
//!
//! [`serialize_boc`](super::serialize_boc) builds a bag's bytes into one buffer. This writes
//! the same bytes, byte for byte, but yields them a chunk at a time, so a bag can be written
//! to a file or a socket without a second copy of it in memory. The cell ordering, the header
//! and the checksum are the standard ones, so what a reader sees is exactly what
//! [`serialize_boc`](super::serialize_boc) produces.

use super::serialize::{byte_width, index_of, push_be, topological};
use super::{crc32c_update, BocOptions, CRC32C_INIT, MAGIC, MAX_CELLS};
use crate::cell::Cell;
use crate::error::CellError;

/// About how many bytes to gather into one body chunk before yielding it.
const CHUNK_TARGET: usize = 16 * 1024;

/// Serializes a bag of cells as a stream of byte chunks, the streaming form of
/// [`serialize_boc`](super::serialize_boc).
///
/// The iterator yields the header, then the cells in chunks of roughly 16 KiB,
/// then the checksum, and the whole of it run together is exactly what
/// [`serialize_boc`](super::serialize_boc) returns for the same roots. The cell ordering and
/// sizes are worked out up front, so what is held past that is one chunk at a time rather than
/// the whole bag.
///
/// # Errors
///
/// Returns [`CellError::Header`] if `roots` is empty, or [`CellError::TooManyCells`] if the
/// graph is larger than [`MAX_CELLS`](super::MAX_CELLS).
pub fn serialize_boc_chunks(roots: &[Cell]) -> Result<BocChunks, CellError> {
    serialize_boc_chunks_with(roots, &BocOptions::default())
}

/// Serializes a bag as a stream of chunks, choosing what to write beyond the cells.
///
/// This is [`serialize_boc_chunks`] with the index and checksum under the caller's control,
/// the streaming form of [`serialize_boc_with`](super::serialize_boc_with).
///
/// # Errors
///
/// As [`serialize_boc_chunks`].
pub fn serialize_boc_chunks_with(
    roots: &[Cell],
    options: &BocOptions,
) -> Result<BocChunks, CellError> {
    if roots.is_empty() {
        return Err(CellError::Header("root count"));
    }
    let (order, children) = topological(roots)?;
    let count = order.len();
    if count > MAX_CELLS {
        return Err(CellError::TooManyCells { limit: MAX_CELLS });
    }
    let ref_size = byte_width(count as u64);

    // One pass over the cells to size the body and, if the index is asked for, record each
    // cell's end offset, which is what the header needs before any cell is written.
    let mut body_len = 0usize;
    let mut offsets = Vec::with_capacity(count);
    for (cell, refs) in order.iter().zip(&children) {
        body_len += 2 + cell.data().len() + refs.len() * ref_size;
        offsets.push(body_len);
    }
    let offset_size = byte_width(body_len as u64);

    let positions = index_of(&order);
    let mut header = Vec::new();
    header.extend_from_slice(&MAGIC);
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
    header.push(flags);
    #[allow(
        clippy::cast_possible_truncation,
        reason = "byte_width returns 1 to 8, which fits u8"
    )]
    let offset_byte = offset_size as u8;
    header.push(offset_byte);
    push_be(&mut header, count as u64, ref_size);
    push_be(&mut header, roots.len() as u64, ref_size);
    push_be(&mut header, 0, ref_size);
    push_be(&mut header, body_len as u64, offset_size);
    for root in roots {
        let index = positions
            .get(root.repr_hash())
            .copied()
            .ok_or(CellError::Malformed("a root was not reachable"))?;
        push_be(&mut header, index as u64, ref_size);
    }
    if options.index {
        for &offset in &offsets {
            push_be(&mut header, offset as u64, offset_size);
        }
    }

    // Fold the header into the running checksum now, so the cell chunks can carry it on.
    let running_crc = crc32c_update(CRC32C_INIT, &header);

    Ok(BocChunks {
        order,
        children,
        ref_size,
        header: Some(header),
        crc_enabled: options.crc32c,
        running_crc,
        cursor: 0,
        phase: Phase::Header,
    })
}

/// Which part of a bag the stream is on.
enum Phase {
    Header,
    Body,
    Crc,
    Done,
}

/// A bag of cells yielded a chunk at a time, built by [`serialize_boc_chunks`].
///
/// Run the chunks together and the bytes are exactly [`serialize_boc`](super::serialize_boc)'s.
pub struct BocChunks {
    order: Vec<Cell>,
    children: Vec<Vec<usize>>,
    ref_size: usize,
    header: Option<Vec<u8>>,
    crc_enabled: bool,
    running_crc: u32,
    cursor: usize,
    phase: Phase,
}

impl Iterator for BocChunks {
    type Item = Vec<u8>;

    fn next(&mut self) -> Option<Vec<u8>> {
        loop {
            match self.phase {
                Phase::Header => {
                    self.phase = Phase::Body;
                    // The header was folded into the running checksum as it was built.
                    return self.header.take();
                }
                Phase::Body => {
                    if self.cursor >= self.order.len() {
                        self.phase = if self.crc_enabled {
                            Phase::Crc
                        } else {
                            Phase::Done
                        };
                        continue;
                    }
                    let mut chunk = Vec::new();
                    while self.cursor < self.order.len() && chunk.len() < CHUNK_TARGET {
                        if let (Some(cell), Some(refs)) =
                            (self.order.get(self.cursor), self.children.get(self.cursor))
                        {
                            let (d1, d2) = cell.stored_descriptors();
                            chunk.push(d1);
                            chunk.push(d2);
                            chunk.extend_from_slice(cell.data());
                            for &index in refs {
                                push_be(&mut chunk, index as u64, self.ref_size);
                            }
                        }
                        self.cursor += 1;
                    }
                    self.running_crc = crc32c_update(self.running_crc, &chunk);
                    return Some(chunk);
                }
                Phase::Crc => {
                    self.phase = Phase::Done;
                    return Some((!self.running_crc).to_le_bytes().to_vec());
                }
                Phase::Done => return None,
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{parse_boc, serialize_boc_with, Builder};

    /// Runs a chunk stream together into the bytes it spells out.
    fn run(chunks: BocChunks) -> Vec<u8> {
        chunks.flatten().collect()
    }

    /// A four-cell bag: a root over two parents that share one child, so the ordering and a
    /// shared reference are both exercised.
    fn shared_child_bag() -> Vec<Cell> {
        let mut child = Builder::new();
        child.store_uint(0xcd, 8).expect("a byte fits");
        let child = child.build().expect("a cell forms");

        let parent = |tag: u64| {
            let mut b = Builder::new();
            b.store_uint(tag, 8).expect("a byte fits");
            b.store_ref(child.clone()).expect("a ref fits");
            b.build().expect("a cell forms")
        };
        let mut root = Builder::new();
        root.store_uint(0xab, 8).expect("a byte fits");
        root.store_ref(parent(0xa1)).expect("a ref fits");
        root.store_ref(parent(0xa2)).expect("a ref fits");
        vec![root.build().expect("a cell forms")]
    }

    #[test]
    fn a_chunk_stream_is_the_whole_serialization() {
        // For every option combination the run-together chunks must equal the one-buffer
        // serializer byte for byte, which is what makes this a drop-in streaming form.
        let roots = shared_child_bag();
        for index in [false, true] {
            for crc32c in [false, true] {
                let options = BocOptions { index, crc32c };
                let streamed = run(serialize_boc_chunks_with(&roots, &options).expect("streams"));
                let whole = serialize_boc_with(&roots, &options).expect("serializes");
                assert_eq!(streamed, whole, "index={index} crc32c={crc32c}");
            }
        }
    }

    #[test]
    fn the_streamed_bytes_parse_back_to_the_same_graph() {
        let roots = shared_child_bag();
        let streamed = run(serialize_boc_chunks(&roots).expect("streams"));
        let parsed = parse_boc(&streamed).expect("the stream parses");
        assert_eq!(parsed.len(), 1);
        assert_eq!(parsed[0].repr_hash(), roots[0].repr_hash());
    }

    #[test]
    fn an_empty_root_set_is_refused() {
        assert!(matches!(
            serialize_boc_chunks(&[]),
            Err(CellError::Header(_))
        ));
    }
}
