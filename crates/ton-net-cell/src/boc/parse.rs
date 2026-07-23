// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Nirapod Labs

//! Reading a bag's cells into a graph, once its header has been checked.

use super::{bit_len, read_header, Header, Reader, MAX_DEPTH};
use crate::cell::{Cell, CellType, MAX_BITS, MAX_REFS};
use crate::error::CellError;

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
/// disagree, [`CellError::TooManyCells`] past [`MAX_CELLS`](super::MAX_CELLS), or
/// [`CellError::TooDeep`] past [`MAX_DEPTH`](super::MAX_DEPTH).
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

/// Reads the cells of a bag whose header has been read, and returns its roots.
///
/// `reader` sits at the first cell and `header` carries the counts the reads below trust,
/// which [`read_header`] has already held to the bytes. Cells are built in the one order a
/// bag stores them, every child before its parent, so each is finished before anything
/// references it.
pub(super) fn read_and_build(
    reader: &mut Reader<'_>,
    header: &Header,
) -> Result<Vec<Cell>, CellError> {
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
