// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Nirapod Labs

//! Computing a cell's representation hashes and depths, the values that are its identity.

use sha2::{Digest, Sha256};

use super::{bits_descriptor, hash_index, level_of, refs_descriptor, Cell, CellType};
use crate::error::CellError;

/// A child's stored identity, enough to hash its parent without holding the child cell.
///
/// A parent's hash is taken over its children's hashes and depths, one per level, so those
/// values are all a parent needs from a child. Carrying them as a summary rather than a whole
/// cell is what lets a bag be hash-verified without building its graph: the reader keeps a
/// summary per cell, tens of bytes, in place of a cell, hundreds.
#[derive(Clone)]
pub struct Summary {
    /// The cell's level mask.
    level_mask: u8,
    /// One hash per significant level, lowest first.
    hashes: Vec<[u8; 32]>,
    /// The depth beside each hash.
    depths: Vec<u16>,
}

impl Summary {
    /// Reads a built cell's identity into a summary.
    pub fn of(cell: &Cell) -> Self {
        let (hashes, depths) = cell.stored();
        Self {
            level_mask: cell.level_mask(),
            hashes: hashes.to_vec(),
            depths: depths.to_vec(),
        }
    }

    /// A summary from parts already computed, as [`summarize`](super::summarize) returns.
    pub fn from_parts(level_mask: u8, hashes: Vec<[u8; 32]>, depths: Vec<u16>) -> Self {
        Self {
            level_mask,
            hashes,
            depths,
        }
    }

    /// The summarised cell's level mask.
    pub fn level_mask(&self) -> u8 {
        self.level_mask
    }

    /// The summarised cell's significant hashes, lowest level first.
    pub fn hashes(&self) -> &[[u8; 32]] {
        &self.hashes
    }

    /// The depth beside each hash.
    pub fn depths(&self) -> &[u16] {
        &self.depths
    }

    /// The identity of the summarised cell itself: its hash at its own level.
    pub fn repr_hash(&self) -> [u8; 32] {
        self.hash_at(level_of(self.level_mask))
    }

    /// Consumes the summary, returning its hashes and depths for a cell to hold.
    pub fn into_parts(self) -> (Vec<[u8; 32]>, Vec<u16>) {
        (self.hashes, self.depths)
    }

    /// The summarised cell's hash at `level`, clamped to its topmost, as [`Cell::hash_at`].
    #[expect(
        clippy::indexing_slicing,
        reason = "clamped to the last hash, and a summary is built with at least one"
    )]
    fn hash_at(&self, level: u8) -> [u8; 32] {
        let index = hash_index(self.level_mask, level);
        let last = self.hashes.len().saturating_sub(1);
        self.hashes[index.min(last)]
    }

    /// The summarised cell's depth at `level`, clamped to its topmost, as [`Cell::depth_at`].
    fn depth_at(&self, level: u8) -> u16 {
        let index = hash_index(self.level_mask, level);
        let last = self.depths.len().saturating_sub(1);
        self.depths.get(index.min(last)).copied().unwrap_or(0)
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
    refs: &[Summary],
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
            repr.extend_from_slice(&child.hash_at(child_level));
        }

        hashes.push(Sha256::digest(&repr).into());
        depths.push(depth);
    }

    Ok((hashes, depths))
}
