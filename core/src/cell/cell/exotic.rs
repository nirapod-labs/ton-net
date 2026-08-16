// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Nirapod Labs

//! A cell's kind: ordinary, or one of the four exotic forms the cell model gives a meaning.

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
    pub(super) fn is_merkle(self) -> bool {
        matches!(self, Self::MerkleProof | Self::MerkleUpdate)
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
}
