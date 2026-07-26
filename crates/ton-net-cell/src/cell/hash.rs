// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Nirapod Labs

//! A cell's identity: its representation hashes and depths, and the rules that compute them.

use sha2::{Digest, Sha256};

use super::{bits_descriptor, hash_index, level_of, refs_descriptor, CellType};
use crate::error::CellError;

/// The most representation hashes a cell can have: one per level a three-bit mask marks,
/// and one besides.
const MAX_HASHES: usize = 4;

/// A cell's identity: one representation hash and depth per level its mask makes significant.
///
/// This is what a parent hashes itself over, what a proof reproduces, and what a bag of cells
/// records beside a cell it carries. It is the whole of a cell's identity and none of its
/// contents, which is what lets a bag be hash-verified without building its graph: a reader
/// keeps one of these per cell, tens of bytes, in place of a cell, hundreds.
///
/// The hashes run lowest significant level first, [`count`](Identity::count) of them, reached
/// by position with [`hash`](Identity::hash) or by level with [`hash_at`](Identity::hash_at).
/// A cell with an empty mask has exactly one. A pruned branch has one per level it marks, and
/// so does each ancestor the mask reaches, up to the nearest Merkle cell: a Merkle cell shifts
/// the mask it covers down by one, so the mask stops there.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Identity {
    /// The cell's level mask, which fixes how many hashes it has and which answers for a level.
    level_mask: u8,
    /// The hash at the lowest significant level, which every cell has.
    hash0: [u8; 32],
    /// The depth beside it.
    depth0: u16,
    /// Everything above the lowest level, held apart and boxed.
    ///
    /// A cell with an empty mask has one hash and no more, and in a bag with no pruned branch
    /// in it that is every cell. Keeping the rest here costs those cells a pointer instead of
    /// the space for three hashes their mask does not call for.
    extra: Option<Box<Extra>>,
}

/// The hashes and depths above the lowest, for a cell significant at more than one level.
///
/// Slots past the cell's own count stay zero, so two identities of the same shape hold the
/// same bytes and equality means what it says.
#[derive(Clone, Debug, PartialEq, Eq)]
struct Extra {
    hashes: [[u8; 32]; MAX_HASHES - 1],
    depths: [u16; MAX_HASHES - 1],
}

impl Identity {
    /// The identity a reference slot holds before a child is put in it.
    ///
    /// A caller passes only the slots it filled, so nothing is ever hashed over this.
    pub(crate) const NONE: Self = Self {
        level_mask: 0,
        hash0: [0u8; 32],
        depth0: 0,
        extra: None,
    };

    /// Room for the hashes a mask calls for, with none of them computed yet.
    ///
    /// The count comes from the mask alone, so the space is taken once rather than grown, and
    /// a mask marking more levels than the cell model defines is refused here rather than
    /// silently truncated.
    fn blank(level_mask: u8) -> Result<Self, CellError> {
        let count = level_mask.count_ones() as usize + 1;
        if count > MAX_HASHES {
            return Err(CellError::Malformed(
                "cell level mask marks more levels than the cell model has",
            ));
        }
        Ok(Self {
            level_mask,
            hash0: [0u8; 32],
            depth0: 0,
            extra: (count > 1).then(|| {
                Box::new(Extra {
                    hashes: [[0u8; 32]; MAX_HASHES - 1],
                    depths: [0u16; MAX_HASHES - 1],
                })
            }),
        })
    }

    /// Records the hash and depth for the level at `index`, counting from the lowest.
    fn set(&mut self, index: usize, hash: [u8; 32], depth: u16) -> Result<(), CellError> {
        let past_the_end =
            || CellError::Malformed("cell has more hashes than its level mask allows");
        if index == 0 {
            self.hash0 = hash;
            self.depth0 = depth;
            return Ok(());
        }
        let extra = self.extra.as_mut().ok_or_else(past_the_end)?;
        *extra.hashes.get_mut(index - 1).ok_or_else(past_the_end)? = hash;
        *extra.depths.get_mut(index - 1).ok_or_else(past_the_end)? = depth;
        Ok(())
    }

    /// The cell's level mask, a three-bit value.
    #[must_use]
    pub fn level_mask(&self) -> u8 {
        self.level_mask
    }

    /// How many hashes and depths the cell has, one per level its mask makes significant.
    ///
    /// This is one more than the mask's set bits, so it is one for a cell with an empty mask
    /// and at most four for any.
    #[must_use]
    pub fn count(&self) -> usize {
        self.level_mask.count_ones() as usize + 1
    }

    /// The hash at `index`, counting from the lowest significant level, or `None` past the end.
    #[must_use]
    pub fn hash(&self, index: usize) -> Option<&[u8; 32]> {
        match index {
            0 => Some(&self.hash0),
            _ if index >= self.count() => None,
            _ => self
                .extra
                .as_ref()
                .and_then(|extra| extra.hashes.get(index - 1)),
        }
    }

    /// The depth beside the hash at `index`, or `None` past the end.
    #[must_use]
    pub fn depth(&self, index: usize) -> Option<u16> {
        match index {
            0 => Some(self.depth0),
            _ if index >= self.count() => None,
            _ => self
                .extra
                .as_ref()
                .and_then(|extra| extra.depths.get(index - 1).copied()),
        }
    }

    /// The hash for `level`, with levels above the cell's own answering with its topmost.
    ///
    /// The fallback is the cell's lowest hash rather than a zero hash. A cell that answered
    /// with zeros would compare equal to every other cell that failed the same way, which is
    /// worse than answering with a hash the cell really has.
    #[must_use]
    pub fn hash_at(&self, level: u8) -> &[u8; 32] {
        let index = hash_index(self.level_mask, level);
        self.hash(index.min(self.count().saturating_sub(1)))
            .unwrap_or(&self.hash0)
    }

    /// The depth for `level`, clamped to the cell's topmost as [`hash_at`](Identity::hash_at) is.
    #[must_use]
    pub fn depth_at(&self, level: u8) -> u16 {
        let index = hash_index(self.level_mask, level);
        self.depth(index.min(self.count().saturating_sub(1)))
            .unwrap_or(self.depth0)
    }

    /// The cell's own identity: its hash at its own level.
    ///
    /// This is the value two cells are the same cell by. It differs from the level-zero hash
    /// exactly where it must: a pruned branch's level-zero hash belongs to the subtree it
    /// replaced, and some other cell may legitimately answer with the same one.
    #[must_use]
    pub fn repr_hash(&self) -> &[u8; 32] {
        self.hash_at(level_of(self.level_mask))
    }
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
pub(super) fn compute(
    data: &[u8],
    bits: u16,
    refs: &[&Identity],
    cell_type: CellType,
    mask: u8,
) -> Result<Identity, CellError> {
    let mut identity = Identity::blank(mask)?;
    let level = level_of(mask);
    let exotic = cell_type != CellType::Ordinary;
    let stored = mask.count_ones() as usize;
    let mut written = 0usize;

    if cell_type == CellType::PrunedBranch {
        // Below its own level a pruned branch is the subtree it replaced.
        for index in 0..stored {
            let hash = read_hash(data, 2 + 32 * index)?;
            let depth = read_depth(data, 2 + 32 * stored + 2 * index)?;
            identity.set(index, hash, depth)?;
        }
        // At its own level it is only a cell, hashed as it stands.
        let (d1, d2) = (refs_descriptor(0, true, mask, level), bits_descriptor(bits));
        let mut sum = Sha256::new();
        sum.update([d1, d2]);
        sum.update(data);
        identity.set(stored, sum.finalize().into(), 0)?;
        written = stored + 1;
    } else {
        let child_level_shift = u8::from(cell_type.is_merkle());
        for this_level in 0..=level {
            // Only a level that opens a new hash index produces a hash.
            if hash_index(mask, this_level) != written {
                continue;
            }
            let child_level = this_level + child_level_shift;
            let (d1, d2) = (
                refs_descriptor(refs.len(), exotic, mask, this_level),
                bits_descriptor(bits),
            );

            // The representation goes into the hash a piece at a time rather than into a buffer
            // that is then hashed. The bytes are the same either way, and this is the innermost
            // loop of the crate: gathering them first costs an allocation and a copy of the
            // cell's data and of every child's hash, per level, per cell.
            let mut sum = Sha256::new();
            sum.update([d1, d2]);
            match written
                .checked_sub(1)
                .and_then(|below| identity.hash(below))
            {
                // The lowest hash is taken over the cell's data.
                None => sum.update(data),
                // A higher hash is taken over the hash below it.
                Some(previous) => sum.update(previous),
            }

            // Every child's depth precedes every child's hash, so the depths are fed here and
            // the hashes below rather than in one pass over the references.
            let mut depth = 0u16;
            for child in refs {
                let child_depth = child.depth_at(child_level);
                depth = depth.max(child_depth.saturating_add(1));
                sum.update(child_depth.to_be_bytes());
            }
            for child in refs {
                sum.update(child.hash_at(child_level));
            }

            identity.set(written, sum.finalize().into(), depth)?;
            written += 1;
        }
    }

    // Every slot the mask calls for has to have been written. A slot left blank would leave
    // the cell answering with a zero hash, which is the one wrong answer that looks like an
    // identity, so it is refused here rather than returned.
    if written != identity.count() {
        return Err(CellError::Malformed(
            "cell has fewer hashes than its level mask calls for",
        ));
    }
    Ok(identity)
}
