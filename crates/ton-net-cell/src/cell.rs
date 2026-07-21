//! The cell: TON's universal container of data and references.

use std::fmt;
use std::sync::Arc;

use crate::slice::Slice;

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
            CellType::Ordinary => None,
            CellType::PrunedBranch => Some(0x01),
            CellType::LibraryReference => Some(0x02),
            CellType::MerkleProof => Some(0x03),
            CellType::MerkleUpdate => Some(0x04),
        }
    }

    /// The kind an exotic cell's leading data byte names, or `None` if it names none.
    #[must_use]
    pub fn from_tag(tag: u8) -> Option<CellType> {
        match tag {
            0x01 => Some(CellType::PrunedBranch),
            0x02 => Some(CellType::LibraryReference),
            0x03 => Some(CellType::MerkleProof),
            0x04 => Some(CellType::MerkleUpdate),
            _ => None,
        }
    }
}

/// A TON cell: up to 1023 bits of data and up to four references.
///
/// A cell is immutable and cheap to clone: clones share one allocation. Cells form a
/// directed acyclic graph, and every TON structure, an account, a block, a contract's
/// code, is a tree of them.
///
/// Read a cell's contents with [`parse`](Cell::parse), which returns a [`Slice`] cursor
/// over its bits and references.
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
/// assert!(roots[0].refs().is_empty());
/// # Ok::<(), ton_net_cell::CellError>(())
/// ```
#[derive(Clone, PartialEq, Eq)]
pub struct Cell {
    inner: Arc<Inner>,
}

#[derive(PartialEq, Eq)]
struct Inner {
    data: Vec<u8>,
    bits: u16,
    refs: Vec<Cell>,
    cell_type: CellType,
    level_mask: u8,
}

impl Cell {
    /// Builds a cell from already validated parts.
    pub(crate) fn from_parts(
        data: Vec<u8>,
        bits: u16,
        refs: Vec<Cell>,
        cell_type: CellType,
        level_mask: u8,
    ) -> Cell {
        Cell {
            inner: Arc::new(Inner {
                data,
                bits,
                refs,
                cell_type,
                level_mask,
            }),
        }
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
    pub fn refs(&self) -> &[Cell] {
        &self.inner.refs
    }

    /// The reference at `index`, or `None` if the cell has no such reference.
    #[must_use]
    pub fn reference(&self, index: usize) -> Option<&Cell> {
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

    /// The cell's level: the highest level its mask marks, or zero for an empty mask.
    #[must_use]
    pub fn level(&self) -> u8 {
        (u8::BITS - self.inner.level_mask.leading_zeros()) as u8
    }

    /// A cursor that reads typed values from the cell's bits and references.
    #[must_use]
    pub fn parse(&self) -> Slice<'_> {
        Slice::new(self)
    }
}

impl fmt::Debug for Cell {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Cell")
            .field("cell_type", &self.inner.cell_type)
            .field("bits", &self.inner.bits)
            .field("refs", &self.inner.refs.len())
            .field("level_mask", &self.inner.level_mask)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
        let cell = |mask| Cell::from_parts(Vec::new(), 0, Vec::new(), CellType::Ordinary, mask);
        assert_eq!(cell(0b000).level(), 0);
        assert_eq!(cell(0b001).level(), 1);
        assert_eq!(cell(0b011).level(), 2);
        assert_eq!(cell(0b111).level(), 3);
        assert_eq!(cell(0b100).level(), 3);
    }
}
