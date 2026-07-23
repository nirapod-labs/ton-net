// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Nirapod Labs

//! The cell: TON's universal container of data and references, and its identity.

use std::fmt;
use std::sync::Arc;

use sha2::{Digest, Sha256};

use crate::error::CellError;
use crate::slice::Slice;

mod dump;

#[cfg(feature = "json")]
pub mod json;

/// The most data bits a cell may hold.
pub const MAX_BITS: u16 = 1023;

/// The most references a cell may hold.
pub const MAX_REFS: usize = 4;

/// The kind of a cell.
///
/// An ordinary cell is plain data and references. The four exotic kinds carry a meaning
/// the cell model itself gives them, named by the first byte of the cell's data, and are
/// what make Merkle proofs possible.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CellType {
    /// A plain cell of data and references.
    Ordinary,
    /// Stands in for a subtree left out of a proof, holding that subtree's hashes and
    /// depths so the tree above it still hashes to the same root.
    PrunedBranch,
    /// Names contract code by hash instead of holding it.
    LibraryReference,
    /// Covers one tree by hash, so a pruned copy can be checked against a known root.
    MerkleProof,
    /// Covers a pair of trees, an old and a new, as a block's state update does.
    MerkleUpdate,
}

impl CellType {
    /// The leading data byte that names this kind, or `None` for an ordinary cell.
    ///
    /// # Examples
    ///
    /// ```
    /// use ton_net_cell::CellType;
    /// assert_eq!(CellType::MerkleProof.tag(), Some(0x03));
    /// assert_eq!(CellType::Ordinary.tag(), None);
    /// ```
    #[must_use]
    pub fn tag(self) -> Option<u8> {
        match self {
            Self::Ordinary => None,
            Self::PrunedBranch => Some(0x01),
            Self::LibraryReference => Some(0x02),
            Self::MerkleProof => Some(0x03),
            Self::MerkleUpdate => Some(0x04),
        }
    }

    /// The kind an exotic cell's leading data byte names, or `None` if it names none.
    #[must_use]
    pub fn from_tag(tag: u8) -> Option<Self> {
        match tag {
            0x01 => Some(Self::PrunedBranch),
            0x02 => Some(Self::LibraryReference),
            0x03 => Some(Self::MerkleProof),
            0x04 => Some(Self::MerkleUpdate),
            _ => None,
        }
    }

    /// Whether this kind covers another tree, so its content sits one level down.
    fn is_merkle(self) -> bool {
        matches!(self, Self::MerkleProof | Self::MerkleUpdate)
    }
}

/// The highest level a mask marks, or zero for an empty mask.
fn level_of(mask: u8) -> u8 {
    #[allow(
        clippy::cast_possible_truncation,
        reason = "mask is a u8, so leading_zeros is at most 8, and u8::BITS - leading_zeros is at most 8, which fits u8"
    )]
    let level = (u8::BITS - mask.leading_zeros()) as u8;
    level
}

/// The mask as it applies at `level`: only the levels below it remain.
fn applied_mask(mask: u8, level: u8) -> u8 {
    if level >= 3 {
        mask
    } else {
        mask & ((1u8 << level) - 1)
    }
}

/// Which of a cell's stored hashes answers for `level`.
fn hash_index(mask: u8, level: u8) -> usize {
    applied_mask(mask, level).count_ones() as usize
}

/// The bit descriptor for a bit count: `floor(b/8) + ceil(b/8)`.
fn bits_descriptor(bits: u16) -> u8 {
    #[allow(
        clippy::cast_possible_truncation,
        reason = "bits is at most MAX_BITS (1023), so floor(bits/8) + ceil(bits/8) is at most 127 + 128 = 255, which fits u8"
    )]
    let descriptor = ((bits / 8) + bits.div_ceil(8)) as u8;
    descriptor
}

/// The refs-and-type descriptor at a level: `r + 8s + 32l`.
fn refs_descriptor(refs: usize, exotic: bool, mask: u8, level: u8) -> u8 {
    #[allow(
        clippy::cast_possible_truncation,
        reason = "refs is a cell's reference count, bounded to at most MAX_REFS (4) by every constructor, so this fits u8"
    )]
    let refs = refs as u8;
    refs + if exotic { 8 } else { 0 } + 32 * applied_mask(mask, level)
}

/// A TON cell: up to 1023 bits of data and up to four references.
///
/// A cell is immutable and cheap to clone: clones share one allocation. Cells form a
/// directed acyclic graph, and every TON structure, an account, a block, a contract's
/// code, is a tree of them.
///
/// Hashes are computed when the cell is built. [`hash`](Cell::hash) is the level-zero
/// hash, which is what a proof reproduces and what a parent references;
/// [`repr_hash`](Cell::repr_hash) identifies the cell itself, and the two differ for a
/// pruned branch. Read a cell's contents with [`parse`](Cell::parse), which returns a
/// [`Slice`] cursor.
///
/// # Examples
///
/// ```
/// use ton_net_cell::{parse_boc, CellType};
///
/// let bytes = [0xb5, 0xee, 0x9c, 0x72, 0x01, 0x01, 0x01, 0x01, 0x00, 0x03, 0x00,
///              0x00, 0x02, 0xab];
/// let roots = parse_boc(&bytes)?;
/// assert_eq!(roots[0].cell_type(), CellType::Ordinary);
/// assert_eq!(roots[0].bit_len(), 8);
/// # Ok::<(), ton_net_cell::CellError>(())
/// ```
#[derive(Clone)]
pub struct Cell {
    inner: Arc<Inner>,
}

struct Inner {
    data: Vec<u8>,
    bits: u16,
    refs: Vec<Cell>,
    cell_type: CellType,
    level_mask: u8,
    /// One hash per level the mask makes significant, lowest level first.
    hashes: Vec<[u8; 32]>,
    /// The depth beside each hash.
    depths: Vec<u16>,
}

/// Reads a 32-byte hash out of `data` at `at`.
fn read_hash(data: &[u8], at: usize) -> Result<[u8; 32], CellError> {
    let slice = data.get(at..at + 32).ok_or(CellError::Malformed(
        "exotic cell is too short for its hash",
    ))?;
    let mut out = [0u8; 32];
    out.copy_from_slice(slice);
    Ok(out)
}

/// Reads a big-endian depth out of `data` at `at`.
fn read_depth(data: &[u8], at: usize) -> Result<u16, CellError> {
    let bytes: [u8; 2] = data
        .get(at..at + 2)
        .and_then(|slice| slice.try_into().ok())
        .ok_or(CellError::Malformed(
            "exotic cell is too short for its depth",
        ))?;
    Ok(u16::from_be_bytes(bytes))
}

impl Cell {
    /// Builds a cell from validated parts, computing its hashes and depths.
    ///
    /// # Errors
    ///
    /// Returns [`CellError::Malformed`] if an exotic cell is too short to hold the
    /// hashes and depths its level mask claims, or if the level mask is not the one the
    /// cell's kind and children imply.
    pub(crate) fn from_parts(
        data: Vec<u8>,
        bits: u16,
        refs: Vec<Self>,
        cell_type: CellType,
        level_mask: u8,
    ) -> Result<Self, CellError> {
        if level_mask != implied_mask(cell_type, &refs, level_mask) {
            return Err(CellError::Malformed(
                "cell level mask is not the one its children imply",
            ));
        }
        let (hashes, depths) = compute(&data, bits, &refs, cell_type, level_mask)?;
        Ok(Self {
            inner: Arc::new(Inner {
                data,
                bits,
                refs,
                cell_type,
                level_mask,
                hashes,
                depths,
            }),
        })
    }

    /// The cell's data bytes.
    ///
    /// The bytes are the stored form: when [`bit_len`](Cell::bit_len) is not a multiple
    /// of eight, the final byte carries the data bits, then a set bit, then zeros. This
    /// is the form the representation hash is taken over.
    #[must_use]
    pub fn data(&self) -> &[u8] {
        &self.inner.data
    }

    /// The number of data bits the cell holds, at most 1023.
    #[must_use]
    pub fn bit_len(&self) -> u16 {
        self.inner.bits
    }

    /// The cell's references, at most four.
    #[must_use]
    pub fn refs(&self) -> &[Self] {
        &self.inner.refs
    }

    /// The reference at `index`, or `None` if the cell has no such reference.
    #[must_use]
    pub fn reference(&self, index: usize) -> Option<&Self> {
        self.inner.refs.get(index)
    }

    /// The cell's kind.
    #[must_use]
    pub fn cell_type(&self) -> CellType {
        self.inner.cell_type
    }

    /// Whether the cell is exotic, meaning any kind other than ordinary.
    #[must_use]
    pub fn is_exotic(&self) -> bool {
        self.inner.cell_type != CellType::Ordinary
    }

    /// The cell's level mask, a three-bit value.
    ///
    /// The mask records which levels the cell is significant at, which governs how many
    /// representation hashes it has. An ordinary cell's mask is the union of its
    /// children's.
    #[must_use]
    pub fn level_mask(&self) -> u8 {
        self.inner.level_mask
    }

    /// The hashes and depths this cell computed, in the order a bag of cells stores them.
    pub(crate) fn stored(&self) -> (&[[u8; 32]], &[u16]) {
        (&self.inner.hashes, &self.inner.depths)
    }

    /// The cell's level: the highest level its mask marks, or zero for an empty mask.
    #[must_use]
    pub fn level(&self) -> u8 {
        level_of(self.inner.level_mask)
    }

    /// The cell's representation hash at level zero, which is its identity.
    ///
    /// At level zero a pruned branch answers with the hash of the subtree it replaced,
    /// so a pruned copy of a tree hashes to the same value as the full tree. This is the
    /// hash a Merkle proof reproduces and the hash a parent cell references.
    ///
    /// For a tree of ordinary cells, which is the common case, this is simply the hash
    /// of the tree.
    #[must_use]
    pub fn hash(&self) -> &[u8; 32] {
        self.hash_at(0)
    }

    /// The cell's hash at its own level, which identifies the cell itself.
    ///
    /// This differs from [`hash`](Cell::hash) exactly where it must: a pruned branch's
    /// level-zero hash is the hash of the subtree it replaced, which some other cell may
    /// legitimately also have, while this hash covers the placeholder as it stands. Two
    /// cells are the same cell when this matches, so this is the identity to share cells
    /// by when serializing.
    #[must_use]
    pub fn repr_hash(&self) -> &[u8; 32] {
        self.hash_at(self.level())
    }

    /// The cell's representation hash at `level`.
    ///
    /// Levels above the cell's own answer with its topmost hash.
    #[must_use]
    // A cell is built with at least one hash and the index is clamped to the last, so
    // this cannot be out of range. It is indexed rather than reached through `get`
    // because the alternative is a fallback value, and the only value available is a
    // zero hash: a cell that answered with one would compare equal to every other cell
    // that failed the same way, which is a worse outcome than the panic being avoided.
    #[expect(
        clippy::indexing_slicing,
        reason = "clamped to the last hash, and a cell always has one"
    )]
    pub fn hash_at(&self, level: u8) -> &[u8; 32] {
        let index = hash_index(self.inner.level_mask, level);
        let last = self.inner.hashes.len().saturating_sub(1);
        &self.inner.hashes[index.min(last)]
    }

    /// The depth of the tree under this cell at level zero.
    #[must_use]
    pub fn depth(&self) -> u16 {
        self.depth_at(0)
    }

    /// The depth of the tree under this cell at `level`.
    #[must_use]
    pub fn depth_at(&self, level: u8) -> u16 {
        let index = hash_index(self.inner.level_mask, level);
        let last = self.inner.depths.len().saturating_sub(1);
        // A depth is stored alongside every hash, so this is in range for the same
        // reason [`Cell::hash_at`] is, and zero is a depth a leaf really has.
        self.inner.depths.get(index.min(last)).copied().unwrap_or(0)
    }

    /// A cursor that reads typed values from the cell's bits and references.
    #[must_use]
    pub fn parse(&self) -> Slice<'_> {
        Slice::new(self)
    }

    /// Renders the cell and the tree below it as text, in the hex bitstring notation.
    ///
    /// Each cell is one line: its data as `x{...}`, whole nibbles in hex and a trailing
    /// partial nibble completed with a set bit and zeros and marked `_`, so `x{}` is empty,
    /// `x{A}` is `1010`, and `x{B_}` is `101`. Every reference is indented one step under
    /// the cell that holds it, and an exotic cell is named by its kind. This is for reading
    /// a tree, not a wire form; [`to_boc`](Cell::to_boc) is the way back to bytes.
    ///
    /// # Examples
    ///
    /// ```
    /// use ton_net_cell::parse_boc;
    /// let bytes = [0xb5, 0xee, 0x9c, 0x72, 0x01, 0x01, 0x01, 0x01, 0x00, 0x03, 0x00,
    ///              0x00, 0x02, 0xab];
    /// let roots = parse_boc(&bytes)?;
    /// assert_eq!(roots[0].dump(), "x{AB}");
    /// # Ok::<(), ton_net_cell::CellError>(())
    /// ```
    #[must_use]
    pub fn dump(&self) -> String {
        dump::hex(self)
    }

    /// Renders the cell and the tree below it as text, one character per data bit.
    ///
    /// This is [`dump`](Cell::dump) with each cell's data written as `b{...}` in binary, a
    /// `0` or `1` for every bit, which needs no completion because it writes them all.
    ///
    /// # Examples
    ///
    /// ```
    /// use ton_net_cell::parse_boc;
    /// let bytes = [0xb5, 0xee, 0x9c, 0x72, 0x01, 0x01, 0x01, 0x01, 0x00, 0x03, 0x00,
    ///              0x00, 0x02, 0xab];
    /// let roots = parse_boc(&bytes)?;
    /// assert_eq!(roots[0].dump_bits(), "b{10101011}");
    /// # Ok::<(), ton_net_cell::CellError>(())
    /// ```
    #[must_use]
    pub fn dump_bits(&self) -> String {
        dump::binary(self)
    }

    /// Serializes this cell, and everything it references, as a single-root bag of cells.
    ///
    /// # Errors
    ///
    /// Returns [`CellError::TooManyCells`] if the graph is larger than the parse limit.
    pub fn to_boc(&self) -> Result<Vec<u8>, CellError> {
        crate::boc::serialize_boc(std::slice::from_ref(self))
    }

    /// Opens a builder holding a copy of this cell's bits and references.
    ///
    /// A cell is immutable, so this is the way to change one: read it into a builder, add to
    /// it or rebuild from it, and [`build`](crate::Builder::build) a new cell.
    ///
    /// # Errors
    ///
    /// Returns [`CellError`] if the bits or references do not fit a builder.
    pub fn to_builder(&self) -> Result<crate::Builder, CellError> {
        self.parse().to_builder()
    }

    /// The two descriptor bytes as a bag of cells stores them.
    ///
    /// These carry the whole level mask, unlike the descriptors inside a representation
    /// hash, which carry only the mask as it applies at the level being hashed.
    pub(crate) fn stored_descriptors(&self) -> (u8, u8) {
        (
            refs_descriptor(
                self.inner.refs.len(),
                self.is_exotic(),
                self.inner.level_mask,
                3,
            ),
            bits_descriptor(self.inner.bits),
        )
    }
}

/// The level mask a cell must carry, given its kind and its children.
///
/// Only a pruned branch chooses its own mask; every other kind derives one. An ordinary
/// cell stands as high as the highest thing below it, a Merkle cell resolves one level of
/// what it covers and so sits one lower, and a library reference stands alone at zero.
///
/// This is checked rather than assumed because the mask is hashed into the cell's
/// identity. A cell whose stored mask is higher than its children justify hashes the same
/// at level zero but answers a different representation hash, so accepting one would let
/// two cells that are equal disagree about what they are.
fn implied_mask(cell_type: CellType, refs: &[Cell], stored: u8) -> u8 {
    let children = refs
        .iter()
        .fold(0u8, |mask, child| mask | child.level_mask());
    match cell_type {
        CellType::PrunedBranch => stored,
        CellType::LibraryReference => 0,
        CellType::MerkleProof | CellType::MerkleUpdate => children >> 1,
        CellType::Ordinary => children,
    }
}

/// Computes every representation hash and depth a cell has.
///
/// The rules follow the cell specification. The representation is
/// `d1 || d2 || body || each reference's depth || each reference's hash`, hashed with
/// SHA-256, where `d1` carries the level mask as it applies at the level being computed.
/// Three cases shape the rest:
///
/// - A pruned branch below its own level answers with the hash and depth it stored for
///   the subtree it replaced. That substitution is what lets a pruned tree hash to the
///   root of the full tree, and so what makes a Merkle proof checkable.
/// - A Merkle cell's content sits one level down, so its references answer one level up.
/// - Above the lowest level, the body is the cell's own previous hash rather than its
///   data.
fn compute(
    data: &[u8],
    bits: u16,
    refs: &[Cell],
    cell_type: CellType,
    mask: u8,
) -> Result<(Vec<[u8; 32]>, Vec<u16>), CellError> {
    let level = level_of(mask);
    let exotic = cell_type != CellType::Ordinary;
    let stored = mask.count_ones() as usize;

    let mut hashes = Vec::with_capacity(stored + 1);
    let mut depths = Vec::with_capacity(stored + 1);

    if cell_type == CellType::PrunedBranch {
        // Below its own level a pruned branch is the subtree it replaced.
        for index in 0..stored {
            hashes.push(read_hash(data, 2 + 32 * index)?);
            depths.push(read_depth(data, 2 + 32 * stored + 2 * index)?);
        }
        // At its own level it is only a cell, hashed as it stands.
        let (d1, d2) = (refs_descriptor(0, true, mask, level), bits_descriptor(bits));
        let mut repr = Vec::with_capacity(2 + data.len());
        repr.push(d1);
        repr.push(d2);
        repr.extend_from_slice(data);
        hashes.push(Sha256::digest(&repr).into());
        depths.push(0);
        return Ok((hashes, depths));
    }

    let child_level_shift = u8::from(cell_type.is_merkle());
    for this_level in 0..=level {
        // Only a level that opens a new hash index produces a hash.
        if hash_index(mask, this_level) != hashes.len() {
            continue;
        }
        let child_level = this_level + child_level_shift;
        let (d1, d2) = (
            refs_descriptor(refs.len(), exotic, mask, this_level),
            bits_descriptor(bits),
        );

        let mut repr = Vec::with_capacity(2 + data.len() + refs.len() * 34);
        repr.push(d1);
        repr.push(d2);
        match hashes.last() {
            // The lowest hash is taken over the cell's data.
            None => repr.extend_from_slice(data),
            // A higher hash is taken over the hash below it.
            Some(previous) => repr.extend_from_slice(previous),
        }

        let mut depth = 0u16;
        for child in refs {
            depth = depth.max(child.depth_at(child_level).saturating_add(1));
        }
        for child in refs {
            repr.extend_from_slice(&child.depth_at(child_level).to_be_bytes());
        }
        for child in refs {
            repr.extend_from_slice(child.hash_at(child_level));
        }

        hashes.push(Sha256::digest(&repr).into());
        depths.push(depth);
    }

    Ok((hashes, depths))
}

impl PartialEq for Cell {
    /// Cells are equal when they are the same cell, by [`repr_hash`](Cell::repr_hash).
    ///
    /// A pruned branch is deliberately not equal to the subtree it replaced, even though
    /// they share a level-zero hash.
    fn eq(&self, other: &Self) -> bool {
        self.repr_hash() == other.repr_hash()
    }
}

impl Eq for Cell {}

impl std::hash::Hash for Cell {
    /// A cell hashes by its [`repr_hash`](Cell::repr_hash), the identity
    /// [`eq`](Cell::eq) compares, so equal cells share a bucket and a cell can key a map.
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.repr_hash().hash(state);
    }
}

impl fmt::Debug for Cell {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Cell")
            .field("cell_type", &self.inner.cell_type)
            .field("bits", &self.inner.bits)
            .field("refs", &self.inner.refs.len())
            .field("level_mask", &self.inner.level_mask)
            .field("hash", &hex(self.hash()))
            .finish()
    }
}

/// Renders bytes as lowercase hex, for `Debug`.
fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    bytes.iter().fold(String::new(), |mut out, b| {
        let _ = write!(out, "{b:02x}");
        out
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Builder;

    /// A one-byte ordinary cell holding `byte`.
    fn cell_of(byte: u64) -> Cell {
        let mut builder = Builder::new();
        builder.store_uint(byte, 8).expect("a byte fits");
        builder.build().expect("well formed")
    }

    #[test]
    fn equal_cells_share_a_hash_key() {
        use std::collections::HashSet;
        let mut set = HashSet::new();
        set.insert(cell_of(0xAB));
        assert!(
            set.contains(&cell_of(0xAB)),
            "an equal cell is the same key"
        );
        assert!(!set.contains(&cell_of(0xCD)), "a different cell is not");
    }

    #[test]
    fn a_cell_returns_to_a_builder() {
        let cell = cell_of(0xAB);
        let rebuilt = cell
            .to_builder()
            .expect("to a builder")
            .build()
            .expect("well formed");
        assert_eq!(rebuilt.repr_hash(), cell.repr_hash());
    }

    #[test]
    fn tags_round_trip_for_every_exotic_kind() {
        for kind in [
            CellType::PrunedBranch,
            CellType::LibraryReference,
            CellType::MerkleProof,
            CellType::MerkleUpdate,
        ] {
            let tag = kind.tag().expect("an exotic kind has a tag");
            assert_eq!(CellType::from_tag(tag), Some(kind));
        }
        assert_eq!(CellType::Ordinary.tag(), None);
        assert_eq!(CellType::from_tag(0x00), None);
        assert_eq!(CellType::from_tag(0x05), None);
    }

    #[test]
    fn level_reads_the_highest_marked_level() {
        assert_eq!(level_of(0b000), 0);
        assert_eq!(level_of(0b001), 1);
        assert_eq!(level_of(0b011), 2);
        assert_eq!(level_of(0b111), 3);
        assert_eq!(level_of(0b100), 3);
    }

    #[test]
    fn a_mask_applies_only_the_levels_below() {
        assert_eq!(applied_mask(0b101, 0), 0b000);
        assert_eq!(applied_mask(0b101, 1), 0b001);
        assert_eq!(applied_mask(0b101, 2), 0b001);
        assert_eq!(applied_mask(0b101, 3), 0b101);
        // A level past the top answers with the whole mask.
        assert_eq!(applied_mask(0b101, 4), 0b101);
    }

    #[test]
    fn hash_indices_step_once_per_marked_level() {
        // A mask marking levels 1 and 3 has three hashes: 0, 1, 2.
        assert_eq!(hash_index(0b101, 0), 0);
        assert_eq!(hash_index(0b101, 1), 1);
        assert_eq!(hash_index(0b101, 2), 1);
        assert_eq!(hash_index(0b101, 3), 2);
    }

    #[test]
    fn descriptors_follow_the_specification() {
        // d2 = floor(b/8) + ceil(b/8).
        assert_eq!(bits_descriptor(0), 0);
        assert_eq!(bits_descriptor(8), 2);
        assert_eq!(bits_descriptor(12), 3);
        assert_eq!(bits_descriptor(1023), 255);
        // d1 = r + 8s + 32l.
        assert_eq!(refs_descriptor(0, false, 0, 0), 0);
        assert_eq!(refs_descriptor(4, false, 0, 0), 4);
        assert_eq!(refs_descriptor(1, true, 0, 0), 9);
        // A pruned branch at its own level: no refs, exotic, one marked level.
        assert_eq!(refs_descriptor(0, true, 1, 1), 40);
        // The same cell at level zero drops the mask.
        assert_eq!(refs_descriptor(0, true, 1, 0), 8);
    }
}
