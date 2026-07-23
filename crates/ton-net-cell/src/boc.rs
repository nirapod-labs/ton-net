// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Nirapod Labs

//! The bag of cells: the serialized form of a cell graph.

use std::collections::{HashMap, HashSet};

use sha2::{Digest, Sha256};

use crate::cell::{Cell, CellType, MAX_BITS, MAX_REFS};
use crate::error::CellError;

mod view;

#[cfg(feature = "compress")]
pub mod compress;

pub use view::BocView;

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

/// A cell as read from the bag, with its references still as indices.
struct RawCell {
    data: Vec<u8>,
    bits: u16,
    refs: Vec<usize>,
    cell_type: CellType,
    level_mask: u8,
    /// The hashes and depths the cell carried ahead of its data, when it carried them.
    stored: Option<Vec<u8>>,
}

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

/// The number of bytes needed to hold `value`, at least one.
fn byte_width(value: u64) -> usize {
    let bits = u64::BITS - value.leading_zeros();
    (bits.div_ceil(8)).max(1) as usize
}

/// Appends the low `width` bytes of `value`, big-endian.
///
/// A width past the eight bytes a `u64` holds asks for a number wider than the value,
/// which no caller here does; writing all eight is what keeps this total.
fn push_be(out: &mut Vec<u8>, value: u64, width: usize) {
    let bytes = value.to_be_bytes();
    out.extend(bytes.into_iter().skip(bytes.len().saturating_sub(width)));
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

/// Determines a cell's kind, and holds an exotic cell to the shape that kind must have.
///
/// Every exotic kind has a fixed reference count, and a pruned branch a fixed body length
/// as well. The checks belong here, at the parse boundary, because a cell that reaches
/// [`Cell::from_parts`] is hashed, and a hash computed over a shape the cell model does
/// not define is a value no other implementation agrees with.
fn classify(
    exotic: bool,
    data: &[u8],
    level_mask: u8,
    ref_count: usize,
) -> Result<CellType, CellError> {
    if !exotic {
        return Ok(CellType::Ordinary);
    }
    let tag = *data
        .first()
        .ok_or(CellError::Malformed("exotic cell has no type byte"))?;
    let cell_type =
        CellType::from_tag(tag).ok_or(CellError::Malformed("unknown exotic cell type"))?;

    let expected_refs = match cell_type {
        CellType::Ordinary => return Ok(cell_type),
        CellType::PrunedBranch | CellType::LibraryReference => 0,
        CellType::MerkleProof => 1,
        CellType::MerkleUpdate => 2,
    };
    if ref_count != expected_refs {
        // A pruned branch is the one that matters. Its hash is computed from the hash it
        // stands in for and never from its children, so a pruned branch allowed to carry
        // children would hash the same whatever hangs beneath it: an attacker-chosen
        // collision on the value this crate calls a cell's identity.
        return Err(CellError::Malformed(
            "exotic cell has the wrong number of references",
        ));
    }

    if cell_type == CellType::PrunedBranch {
        // A pruned branch carries its level mask twice, in the descriptor and in the
        // cell body, and only the descriptor copy is hashed. Two copies that disagree
        // would leave a cell whose body says one thing and whose identity says another,
        // so the disagreement is refused rather than resolved.
        let stored = *data
            .get(1)
            .ok_or(CellError::Malformed("pruned branch has no mask byte"))?;
        if stored != level_mask {
            return Err(CellError::Malformed(
                "pruned branch mask disagrees with its descriptor",
            ));
        }
        // A pruned branch stands in for a subtree at some level, so it has to have one.
        // At level zero it stores no hash at all and answers with its own, which is a
        // shape that stands in for nothing.
        if stored == 0 {
            return Err(CellError::Malformed("pruned branch has no level"));
        }
        // One hash and one depth per marked level, after the type and mask bytes, and
        // nothing else: an exact length leaves no trailing bytes to carry a second
        // meaning past the ones the reads below index.
        let levels = stored.count_ones() as usize;
        if data.len() != 2 + levels * 34 {
            return Err(CellError::Malformed(
                "pruned branch length disagrees with its level mask",
            ));
        }
    }
    Ok(cell_type)
}

/// Parses a bag of cells and returns its root cells.
///
/// A bag holds a whole cell graph plus the indices of the roots it is read from. Most
/// bags have one root; a liteserver's account proof has two.
///
/// # Errors
///
/// Returns [`CellError::NotABagOfCells`] if the magic does not match,
/// [`CellError::Truncated`] if the bytes end early, [`CellError::Header`] if a header
/// field is out of range, [`CellError::BadReference`] if a reference is out of range or
/// does not point forward, [`CellError::Malformed`] if a cell's descriptors and data
/// disagree, [`CellError::TooManyCells`] past [`MAX_CELLS`], or [`CellError::TooDeep`]
/// past [`MAX_DEPTH`].
///
/// # Examples
///
/// ```
/// use ton_net_cell::parse_boc;
///
/// let bytes = [0xb5, 0xee, 0x9c, 0x72, 0x01, 0x01, 0x01, 0x01, 0x00, 0x03, 0x00,
///              0x00, 0x02, 0xab];
/// let roots = parse_boc(&bytes)?;
/// assert_eq!(roots.len(), 1);
/// assert_eq!(roots[0].data(), &[0xab]);
/// # Ok::<(), ton_net_cell::CellError>(())
/// ```
pub fn parse_boc(bytes: &[u8]) -> Result<Vec<Cell>, CellError> {
    let mut reader = Reader { bytes, at: 0 };
    let header = read_header(&mut reader, bytes)?;
    read_and_build(&mut reader, &header)
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

/// Reads and checks a bag's header, leaving `reader` at the first cell.
///
/// Everything a bag states about itself is checked here before a cell is read: the magic,
/// the field sizes, the checksum over the whole bag, that the counts are in range, and that
/// the stated cell-area size accounts for exactly the bytes that remain. A header that
/// passes describes a bag whose cells can be read without another check on the shape.
fn read_header(reader: &mut Reader<'_>, bytes: &[u8]) -> Result<Header, CellError> {
    if reader.take(4)? != MAGIC {
        return Err(CellError::NotABagOfCells);
    }

    let flags = reader.byte()?;
    let has_index = flags & 0x80 != 0;
    let has_checksum = flags & 0x40 != 0;
    let ref_size = usize::from(flags & 0x07);
    let offset_size = usize::from(reader.byte()?);
    if !(1..=4).contains(&ref_size) {
        return Err(CellError::Header("reference size"));
    }
    if !(1..=8).contains(&offset_size) {
        return Err(CellError::Header("offset size"));
    }

    // A checksum, when present, trails the whole bag and covers everything before it.
    // Checking it first means corrupt bytes are rejected before anything is built.
    if has_checksum {
        let split = bytes.len().checked_sub(4).ok_or(CellError::Truncated)?;
        let (body, tail) = bytes.split_at(split);
        let stored = u32::from_le_bytes(tail.try_into().map_err(|_| CellError::Truncated)?);
        if crc32c(body) != stored {
            return Err(CellError::Checksum);
        }
    }

    #[allow(
        clippy::cast_possible_truncation,
        reason = "ref_size is at most 4, so this is under 2^32"
    )]
    let count = reader.uint(ref_size)? as usize;
    #[allow(
        clippy::cast_possible_truncation,
        reason = "ref_size is at most 4, so this is under 2^32"
    )]
    let roots = reader.uint(ref_size)? as usize;
    #[allow(
        clippy::cast_possible_truncation,
        reason = "ref_size is at most 4, so this is under 2^32"
    )]
    let absent = reader.uint(ref_size)? as usize;
    // Unlike the reads above, this one is as wide as offset_size allows, which is eight
    // bytes, so it can name a bag larger than a 32-bit target can address. Refusing is
    // what keeps the check below meaningful: a size narrowed to fit would let a bag claim
    // one length, carry another, and still pass.
    let Ok(cell_area) = usize::try_from(reader.uint(offset_size)?) else {
        return Err(CellError::Header("cell area size"));
    };

    // An absent cell is a reference to a cell the bag does not carry, which only the
    // format's incremental-update use has. A bag holding one cannot be read whole.
    if absent != 0 {
        return Err(CellError::Header("absent cells"));
    }
    if count > MAX_CELLS {
        return Err(CellError::TooManyCells { limit: MAX_CELLS });
    }
    if roots == 0 || roots > count {
        return Err(CellError::Header("root count"));
    }
    // Every cell costs at least its two descriptor bytes, so a count the remaining bytes
    // could not hold is truncation. Checked before allocating for the count.
    if count.saturating_mul(2) > reader.remaining() {
        return Err(CellError::Truncated);
    }

    let mut root_list = Vec::with_capacity(roots);
    for _ in 0..roots {
        #[allow(
            clippy::cast_possible_truncation,
            reason = "ref_size is at most 4, so this is under 2^32"
        )]
        let index = reader.uint(ref_size)? as usize;
        if index >= count {
            return Err(CellError::BadReference);
        }
        root_list.push(index);
    }
    if has_index {
        // The index only repeats where each cell starts, which this reader already knows.
        reader.take(count.saturating_mul(offset_size))?;
    }

    // The header states how many bytes the cells take. Holding a bag to its own statement
    // leaves no unread tail to hide bytes in, and rejects a bag that claims a size it does
    // not carry rather than reading whatever happens to follow.
    let stated_end = reader
        .consumed()
        .checked_add(cell_area)
        .ok_or(CellError::Header("cell area size"))?;
    let body_end = if has_checksum {
        bytes.len().saturating_sub(4)
    } else {
        bytes.len()
    };
    if stated_end != body_end {
        return Err(CellError::Header("cell area size"));
    }

    Ok(Header {
        count,
        ref_size,
        root_list,
        has_index,
        has_checksum,
        cell_area,
        body_offset: reader.consumed(),
    })
}

/// Reads the cells of a bag whose header has been read, and returns its roots.
///
/// `reader` sits at the first cell and `header` carries the counts the reads below trust,
/// which [`read_header`] has already held to the bytes. Cells are built in the one order a
/// bag stores them, every child before its parent, so each is finished before anything
/// references it.
fn read_and_build(reader: &mut Reader<'_>, header: &Header) -> Result<Vec<Cell>, CellError> {
    let count = header.count;
    let ref_size = header.ref_size;

    let mut raw = Vec::with_capacity(count);
    for index in 0..count {
        let d1 = reader.byte()?;
        let d2 = reader.byte()?;
        // The field is three bits wide and the cell model allows four references, so the
        // top three values describe a cell no TON implementation will build.
        let ref_count = usize::from(d1 & 7);
        if ref_count > MAX_REFS {
            return Err(CellError::Malformed("cell has more than four references"));
        }
        let exotic = d1 & 8 != 0;
        let level_mask = d1 >> 5;

        // A cell may carry its own hashes and depths ahead of its data, one of each per
        // level its mask marks and one more besides. A whole block arrives this way; a
        // Merkle proof does not, which is why the read path never met it. None of it is
        // taken on trust: it is checked below against what the cell's own contents give,
        // so a bag that describes itself wrongly is refused rather than believed.
        let stored = if d1 & 16 != 0 {
            let per_level = level_mask.count_ones() as usize + 1;
            Some(reader.take(per_level * (32 + 2))?.to_vec())
        } else {
            None
        };

        let data = reader.take(usize::from((d2 >> 1) + (d2 & 1)))?.to_vec();
        let bits = bit_len(d2, &data)?;
        if bits > MAX_BITS {
            return Err(CellError::Malformed("cell holds more than 1023 bits"));
        }
        let cell_type = classify(exotic, &data, level_mask, ref_count)?;

        let mut refs = Vec::with_capacity(ref_count);
        for _ in 0..ref_count {
            #[allow(
                clippy::cast_possible_truncation,
                reason = "ref_size is at most 4, so this is under 2^32"
            )]
            let target = reader.uint(ref_size)? as usize;
            // References point strictly forward, which is what keeps the graph acyclic.
            if target >= count || target <= index {
                return Err(CellError::BadReference);
            }
            refs.push(target);
        }

        raw.push(RawCell {
            data,
            bits,
            refs,
            cell_type,
            level_mask,
            stored,
        });
    }

    // References point forward, so a descending pass meets every child before its parent.
    // Depths accumulate in that same descending order, so position k holds cell
    // `count-1-k`, which is the convention the build below reads its children by.
    let mut depth: Vec<usize> = Vec::with_capacity(count);
    for raw_cell in raw.iter().rev() {
        let mut deepest = 0usize;
        for &target in &raw_cell.refs {
            deepest = deepest.max(depth.get(count - 1 - target).copied().unwrap_or(0) + 1);
        }
        if deepest > MAX_DEPTH {
            return Err(CellError::TooDeep { limit: MAX_DEPTH });
        }
        depth.push(deepest);
    }

    // Built in the same descending order. Position k in `built` holds cell `count-1-k`.
    let mut built: Vec<Cell> = Vec::with_capacity(count);
    for raw_cell in raw.iter().rev() {
        let mut refs = Vec::with_capacity(raw_cell.refs.len());
        for &target in &raw_cell.refs {
            let child = built
                .get(count - 1 - target)
                .ok_or(CellError::BadReference)?;
            refs.push(child.clone());
        }
        let cell = Cell::from_parts(
            raw_cell.data.clone(),
            raw_cell.bits,
            refs,
            raw_cell.cell_type,
            raw_cell.level_mask,
        )?;
        if let Some(stored) = &raw_cell.stored {
            check_stored(&cell, stored)?;
        }
        built.push(cell);
    }

    header
        .root_list
        .iter()
        .map(|&index| {
            built
                .get(count - 1 - index)
                .cloned()
                .ok_or(CellError::BadReference)
        })
        .collect()
}

/// Holds a cell to the hashes and depths it carried.
///
/// The stored copies are never used: the cell's identity comes from its own contents
/// either way. What they are good for is disagreement, which means the sender computed
/// something this crate did not, and there is no reading of that worth continuing from.
fn check_stored(cell: &Cell, stored: &[u8]) -> Result<(), CellError> {
    let (hashes, depths) = cell.stored();
    if stored.len() != hashes.len() * 32 + depths.len() * 2 {
        return Err(CellError::Malformed(
            "cell stores a different number of hashes than its level mask allows",
        ));
    }
    for (index, hash) in hashes.iter().enumerate() {
        if stored.get(index * 32..index * 32 + 32) != Some(&hash[..]) {
            return Err(CellError::Malformed(
                "cell stores a hash its contents do not give",
            ));
        }
    }
    let base = hashes.len() * 32;
    for (index, depth) in depths.iter().enumerate() {
        let at = base + index * 2;
        if stored.get(at..at + 2) != Some(&depth.to_be_bytes()[..]) {
            return Err(CellError::Malformed(
                "cell stores a depth its contents do not give",
            ));
        }
    }
    Ok(())
}

/// Orders every cell reachable from `roots` so each comes before the cells it
/// references, which is the order a bag of cells stores them in.
///
/// Cells are shared by representation hash, so a subtree reached by two parents is
/// stored once. Reverse post-order depth-first search gives the ordering, and the walk
/// is iterative so a deep graph cannot overflow the stack.
fn topological(roots: &[Cell]) -> Result<(Vec<Cell>, Vec<Vec<usize>>), CellError> {
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
fn index_of(order: &[Cell]) -> HashMap<[u8; 32], usize> {
    order
        .iter()
        .enumerate()
        .map(|(index, cell)| (*cell.repr_hash(), index))
        .collect()
}

/// What to write into a bag of cells beyond the cells themselves.
///
/// The format carries two optional pieces past the header. An index gives the offset of
/// each cell so a reader can reach one without walking the bag; a CRC-32C checksum trails
/// the whole bag so a reader can refuse corrupted bytes before building anything. Neither
/// changes which cells the bag holds, only how a reader may work over it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BocOptions {
    /// Write the per-cell offset index.
    pub index: bool,
    /// Write the trailing CRC-32C checksum.
    pub crc32c: bool,
}

impl Default for BocOptions {
    /// A checksum and no index, the form [`serialize_boc`] writes.
    fn default() -> Self {
        Self {
            index: false,
            crc32c: true,
        }
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
/// the graph is larger than [`MAX_CELLS`].
///
/// # Examples
///
/// ```
/// use ton_net_cell::{parse_boc, serialize_boc};
///
/// let bytes = [0xb5, 0xee, 0x9c, 0x72, 0x01, 0x01, 0x01, 0x01, 0x00, 0x03, 0x00,
///              0x00, 0x02, 0xab];
/// let roots = parse_boc(&bytes)?;
/// let again = parse_boc(&serialize_boc(&roots)?)?;
/// assert_eq!(roots[0].hash(), again[0].hash());
/// # Ok::<(), ton_net_cell::CellError>(())
/// ```
pub fn serialize_boc(roots: &[Cell]) -> Result<Vec<u8>, CellError> {
    serialize_boc_with(roots, &BocOptions::default())
}

/// Serializes a cell graph as a bag of cells, choosing what to write beyond the cells.
///
/// This is [`serialize_boc`] with the index and checksum under the caller's control. A bag
/// with an index states where each cell begins, and a bag with a checksum can be refused on
/// the way back in if it is corrupt. Multiple roots are written by passing more than one:
/// the shared cells beneath them are still stored once.
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
        body.push(d1);
        body.push(d2);
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

#[cfg(test)]
mod tests {
    use super::*;

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
