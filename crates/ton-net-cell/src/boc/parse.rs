// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Nirapod Labs

//! Reading a bag's cells into a graph, once its header has been checked.

use std::sync::Arc;

use super::{bit_len, read_header, Header, Reader, MAX_DEPTH};
use crate::cell::{summarize, Cell, CellType, Identity, Payload, Refs, Span, MAX_BITS, MAX_REFS};
use crate::error::CellError;

/// A cell as read from the bag, with its references still as indices and its bytes still
/// in the bag.
///
/// The data and the stored hashes are where they were rather than copied out. A bag is one
/// run of bytes and every cell's contents are already inside it, so a read that copies them
/// out pays an allocation and a copy per cell for bytes it is holding either way.
struct RawCell {
    data: Span,
    bits: u16,
    /// Where each reference points, as a position among the bag's cells.
    ///
    /// Inline, because a vector here is an allocation per cell for at most four small
    /// numbers, and a bag is bounded well inside what they fit in.
    refs: [u32; MAX_REFS],
    ref_count: u8,
    cell_type: CellType,
    level_mask: u8,
    /// Where the hashes and depths the cell carried ahead of its data sit, when it carried them.
    stored: Option<Span>,
}

impl RawCell {
    /// The positions this cell references, in order.
    fn refs(&self) -> &[u32] {
        self.refs.get(..usize::from(self.ref_count)).unwrap_or(&[])
    }
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

/// Reads a bag's cells into raw form, references still as indices, and checks each cell's
/// shape as it goes.
///
/// `reader` sits at the first cell and `header` carries the counts the reads below trust,
/// which [`read_header`] has already held to the bytes. The raw cells come back in bag
/// order, every cell ahead of the ones it references.
fn read_raw(reader: &mut Reader<'_>, header: &Header) -> Result<Vec<RawCell>, CellError> {
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
        // Merkle proof does not. None of it is taken on trust: it is checked against what
        // the cell's own contents give, so a bag that describes itself wrongly is refused.
        let stored = if d1 & 16 != 0 {
            let per_level = level_mask.count_ones() as usize + 1;
            let at = reader.consumed();
            let taken = reader.take(per_level * (32 + 2))?;
            Some(Span::new(at, taken.len())?)
        } else {
            None
        };

        let at = reader.consumed();
        let data = reader.take(usize::from((d2 >> 1) + (d2 & 1)))?;
        let span = Span::new(at, data.len())?;
        let bits = bit_len(d2, data)?;
        if bits > MAX_BITS {
            return Err(CellError::Malformed("cell holds more than 1023 bits"));
        }
        let cell_type = classify(exotic, data, level_mask, ref_count)?;

        let mut refs = [0u32; MAX_REFS];
        for slot in refs.get_mut(..ref_count).ok_or(CellError::BadReference)? {
            #[allow(
                clippy::cast_possible_truncation,
                reason = "ref_size is at most 4, so this is under 2^32"
            )]
            let target = reader.uint(ref_size)? as usize;
            // References point strictly forward, which is what keeps the graph acyclic.
            if target >= count || target <= index {
                return Err(CellError::BadReference);
            }
            *slot = u32::try_from(target).map_err(|_| CellError::BadReference)?;
        }

        raw.push(RawCell {
            data: span,
            bits,
            refs,
            #[allow(
                clippy::cast_possible_truncation,
                reason = "held to MAX_REFS above, so this is at most four"
            )]
            ref_count: ref_count as u8,
            cell_type,
            level_mask,
            stored,
        });
    }
    Ok(raw)
}

/// Refuses a graph deeper than [`MAX_DEPTH`](super::MAX_DEPTH).
///
/// References point forward, so a descending pass meets every child before its parent, and
/// depths accumulate in that order: position k holds the depth of cell `count - 1 - k`,
/// the convention the builds below read their children by.
fn check_depths(raw: &[RawCell], count: usize) -> Result<(), CellError> {
    let mut depth: Vec<usize> = Vec::with_capacity(count);
    for raw_cell in raw.iter().rev() {
        let mut deepest = 0usize;
        for &target in raw_cell.refs() {
            let target = target as usize;
            deepest = deepest.max(depth.get(count - 1 - target).copied().unwrap_or(0) + 1);
        }
        if deepest > MAX_DEPTH {
            return Err(CellError::TooDeep { limit: MAX_DEPTH });
        }
        depth.push(deepest);
    }
    Ok(())
}

/// The bag's root cells, read from the positions the header names in a descending build.
fn roots<T: Clone>(built: &[T], header: &Header, count: usize) -> Result<Vec<T>, CellError> {
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

/// Reads the cells of a bag whose header has been read, and returns its roots.
///
/// Cells are built in the one order a bag stores them, every child before its parent, so
/// each is finished before anything references it.
pub(super) fn read_and_build(
    reader: &mut Reader<'_>,
    header: &Header,
) -> Result<Vec<Cell>, CellError> {
    let count = header.count;
    // One buffer for the bag, shared by every cell built from it, in place of a copy of
    // each cell's bytes.
    let payload: Arc<[u8]> = Arc::from(reader.bytes);
    let raw = read_raw(reader, header)?;
    check_depths(&raw, count)?;

    // Built in the same descending order. Position k in `built` holds cell `count-1-k`.
    let mut built: Vec<Cell> = Vec::with_capacity(count);
    for raw_cell in raw.iter().rev() {
        let mut refs = Refs::None;
        for &target in raw_cell.refs() {
            let child = built
                .get(count - 1 - target as usize)
                .ok_or(CellError::BadReference)?;
            refs.push(child.clone())?;
        }
        let cell = Cell::from_parts(
            Payload::window(&payload, raw_cell.data)?,
            raw_cell.bits,
            refs,
            raw_cell.cell_type,
            raw_cell.level_mask,
        )?;
        if let Some(stored) = &raw_cell.stored {
            check_stored(cell.identity(), stored.of(&payload)?)?;
        }
        built.push(cell);
    }

    roots(&built, header, count)
}

/// Hash-verifies a bag's cells without building its graph, and returns its roots' identities.
///
/// This reads and checks every cell exactly as [`read_and_build`] does, but keeps a summary
/// per cell, tens of bytes, rather than a whole cell, so a large bag can be verified and its
/// root hashes read at a fraction of the memory the graph would take. The summaries feed each
/// other bottom up through [`summarize`], the same hashing a built cell runs.
///
/// # Errors
///
/// As [`read_and_build`], for the cells it reads and the identities it computes.
pub(super) fn verify_roots(
    reader: &mut Reader<'_>,
    header: &Header,
) -> Result<Vec<[u8; 32]>, CellError> {
    let count = header.count;
    // Nothing is built here, so the bag's own bytes serve and no buffer is taken.
    let bytes = reader.bytes;
    let raw = read_raw(reader, header)?;
    check_depths(&raw, count)?;

    // Position k in `identities` holds cell `count-1-k`, as `built` does in read_and_build.
    let mut identities: Vec<Identity> = Vec::with_capacity(count);
    for raw_cell in raw.iter().rev() {
        // The children are borrowed out of the identities already kept, so a cell costs no
        // allocation to look at. The borrows end with the block, which is what lets the
        // identity this produces be pushed onto the same vector.
        let identity = {
            let unfilled = Identity::NONE;
            let mut children = [&unfilled; MAX_REFS];
            for (slot, &target) in children.iter_mut().zip(raw_cell.refs()) {
                *slot = identities
                    .get(count - 1 - target as usize)
                    .ok_or(CellError::BadReference)?;
            }
            let children = children
                .get(..raw_cell.refs().len())
                .ok_or(CellError::BadReference)?;
            summarize(
                raw_cell.data.of(bytes)?,
                raw_cell.bits,
                children,
                raw_cell.cell_type,
                raw_cell.level_mask,
            )?
        };
        if let Some(stored) = &raw_cell.stored {
            check_stored(&identity, stored.of(bytes)?)?;
        }
        identities.push(identity);
    }

    let roots = roots(&identities, header, count)?;
    Ok(roots.iter().map(|identity| *identity.repr_hash()).collect())
}

/// A bag's cells as they were read, before any of them is built.
///
/// Reading a bag and building its cells are two costs, and only the second one is per cell.
/// A reader that keeps this has paid the first in full, which is what lets it build cell
/// after cell without going back to the bytes.
pub(super) struct RawCells {
    cells: Vec<RawCell>,
    /// The bag the spans above are windows on, kept because the cells built from it point
    /// into it.
    payload: Arc<[u8]>,
}

impl RawCells {
    /// How many cells the bag holds.
    pub(super) fn len(&self) -> usize {
        self.cells.len()
    }
}

/// Reads and checks every cell of a bag whose header has been read, building none of them.
///
/// # Errors
///
/// As [`read_and_build`], for the cells it reads.
pub(super) fn read_cells(reader: &mut Reader<'_>, header: &Header) -> Result<RawCells, CellError> {
    let payload: Arc<[u8]> = Arc::from(reader.bytes);
    let cells = read_raw(reader, header)?;
    check_depths(&cells, header.count)?;
    Ok(RawCells { cells, payload })
}

/// The cells built from a bag so far, and the scratch a repeated build reuses.
///
/// A walk marks what it reaches with a generation number rather than a flag, so opening one
/// costs a counter where clearing a flag vector would cost the length of the bag. That is
/// what keeps reading one cell proportional to its own subtree rather than to the bag, however
/// many cells have been read before it.
pub(super) struct Build {
    built: Vec<Option<Cell>>,
    /// The walk that last reached each cell. Equal to `generation` means reached by this one.
    seen: Vec<u32>,
    generation: u32,
}

impl Build {
    /// Room to build the cells of a bag holding `count` of them, with none built.
    pub(super) fn new(count: usize) -> Self {
        Self {
            built: vec![None; count],
            seen: vec![0; count],
            generation: 0,
        }
    }

    /// The cell at `index`, if it has been built.
    pub(super) fn get(&self, index: usize) -> Option<Cell> {
        self.built.get(index).cloned().flatten()
    }

    /// How many cells have been built and kept.
    pub(super) fn count(&self) -> usize {
        self.built.iter().flatten().count()
    }

    /// Opens a walk and returns the generation it marks cells with.
    fn open_walk(&mut self) -> u32 {
        if let Some(next) = self.generation.checked_add(1) {
            self.generation = next;
        } else {
            // A generation that wrapped would read a mark left by an older walk as one of its
            // own, so the marks go back to nothing and counting starts again.
            self.seen.fill(0);
            self.generation = 1;
        }
        self.generation
    }
}

/// Builds the cell at `index` and every cell it reaches that is not built already, keeping
/// each one.
///
/// `index` is a position among the bag's cells in stored order, the roots first. References
/// point strictly forward, which [`read_cells`] has already checked, so a cell's subtree is a
/// set of cells at higher indices and building in descending order reaches every child before
/// its parent.
///
/// A cell is only ever built together with its whole subtree, so one already built needs
/// nothing below it walked again.
///
/// # Errors
///
/// [`CellError::BadReference`] if `index` is past the bag's cell count, and otherwise as
/// [`read_and_build`], for the cells it builds.
pub(super) fn build_at(raw: &RawCells, state: &mut Build, index: usize) -> Result<Cell, CellError> {
    if index >= raw.cells.len() {
        return Err(CellError::BadReference);
    }
    if let Some(cell) = state.get(index) {
        return Ok(cell);
    }

    // Walk what the requested cell reaches and has not been built, collecting the positions
    // rather than scanning the bag for them afterwards.
    let generation = state.open_walk();
    let mut order: Vec<usize> = Vec::new();
    let mut stack = vec![index];
    while let Some(position) = stack.pop() {
        if state.built.get(position).is_some_and(Option::is_some) {
            continue;
        }
        match state.seen.get_mut(position) {
            Some(mark) if *mark != generation => *mark = generation,
            _ => continue,
        }
        order.push(position);
        for &target in raw
            .cells
            .get(position)
            .ok_or(CellError::BadReference)?
            .refs()
        {
            stack.push(target as usize);
        }
    }
    order.sort_unstable();

    for position in order.into_iter().rev() {
        let raw_cell = raw.cells.get(position).ok_or(CellError::BadReference)?;
        let mut refs = Refs::None;
        for &target in raw_cell.refs() {
            let child = state
                .built
                .get(target as usize)
                .and_then(Option::as_ref)
                .ok_or(CellError::BadReference)?;
            refs.push(child.clone())?;
        }
        let cell = Cell::from_parts(
            Payload::window(&raw.payload, raw_cell.data)?,
            raw_cell.bits,
            refs,
            raw_cell.cell_type,
            raw_cell.level_mask,
        )?;
        if let Some(stored) = &raw_cell.stored {
            check_stored(cell.identity(), stored.of(&raw.payload)?)?;
        }
        if let Some(slot) = state.built.get_mut(position) {
            *slot = Some(cell);
        }
    }

    state.get(index).ok_or(CellError::BadReference)
}

/// Builds one cell of the bag, and only the cells it reaches, leaving the rest unbuilt.
///
/// This reads the bag to know its structure and to check it, builds the requested cell's
/// subtree, and drops the rest. A caller reading more than one cell of the same bag wants
/// [`read_cells`] and [`build_at`] instead, which read once and keep what they build.
///
/// # Errors
///
/// [`CellError::BadReference`] if `index` is past the bag's cell count, and otherwise as
/// [`read_and_build`], for the cells it reads and builds.
pub(super) fn build_cell(
    reader: &mut Reader<'_>,
    header: &Header,
    index: usize,
) -> Result<Cell, CellError> {
    if index >= header.count {
        return Err(CellError::BadReference);
    }
    let raw = read_cells(reader, header)?;
    let mut state = Build::new(header.count);
    build_at(&raw, &mut state, index)
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

/// Holds a cell's computed identity to the hashes and depths it carried.
///
/// The stored copies are never used: the cell's identity comes from its own contents
/// either way. What they are good for is disagreement, which means the sender computed
/// something this crate did not, and there is no reading of that worth continuing from.
/// It takes the computed identity rather than a cell, so the graph-building read and the
/// identity-only read can both reach it.
fn check_stored(identity: &Identity, stored: &[u8]) -> Result<(), CellError> {
    let count = identity.count();
    if stored.len() != count * 34 {
        return Err(CellError::Malformed(
            "cell stores a different number of hashes than its level mask allows",
        ));
    }
    let missing = || CellError::Malformed("cell has fewer hashes than its level mask calls for");
    for index in 0..count {
        let hash = identity.hash(index).ok_or_else(missing)?;
        if stored.get(index * 32..index * 32 + 32) != Some(&hash[..]) {
            return Err(CellError::Malformed(
                "cell stores a hash its contents do not give",
            ));
        }
    }
    let base = count * 32;
    for index in 0..count {
        let depth = identity.depth(index).ok_or_else(missing)?;
        let at = base + index * 2;
        if stored.get(at..at + 2) != Some(&depth.to_be_bytes()[..]) {
            return Err(CellError::Malformed(
                "cell stores a depth its contents do not give",
            ));
        }
    }
    Ok(())
}
