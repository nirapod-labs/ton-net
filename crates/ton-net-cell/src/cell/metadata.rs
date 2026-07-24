// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Nirapod Labs

//! A cell's stored identity: the hashes and depths a bag of cells records for it.
//!
//! Every cell carries the hashes and depths its representation rules give it, computed once
//! when the cell is built. This module reads them back out, for the cell and for each of its
//! references one level down, without recomputing anything. The lazy and streaming bag paths
//! read this to know a subtree's identity before they build it, and an inspector reads it to
//! see a cell's hashes as the wire form records them.

use super::Cell;

/// The identity a bag of cells records for a cell.
///
/// The `hashes` and `depths` run lowest significant level first, one pair per level the
/// [`level_mask`](Metadata::level_mask) makes significant, so an ordinary cell has one pair
/// and a cell significant at several levels has several. `refs` carries the same for each
/// reference, in order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Metadata {
    /// The cell's level mask.
    pub level_mask: u8,
    /// One hash per significant level, lowest first.
    pub hashes: Vec<[u8; 32]>,
    /// The depth beside each hash.
    pub depths: Vec<u16>,
    /// The identity of each reference, in order.
    pub refs: Vec<RefMetadata>,
}

/// The stored identity of one reference.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RefMetadata {
    /// The reference's level mask.
    pub level_mask: u8,
    /// One hash per significant level, lowest first.
    pub hashes: Vec<[u8; 32]>,
    /// The depth beside each hash.
    pub depths: Vec<u16>,
}

/// Reads a cell's stored identity, and its references', without recomputing anything.
pub(super) fn of(cell: &Cell) -> Metadata {
    let (hashes, depths) = cell.stored();
    Metadata {
        level_mask: cell.level_mask(),
        hashes: hashes.to_vec(),
        depths: depths.to_vec(),
        refs: cell.refs().iter().map(ref_of).collect(),
    }
}

/// Reads one reference's stored identity.
fn ref_of(cell: &Cell) -> RefMetadata {
    let (hashes, depths) = cell.stored();
    RefMetadata {
        level_mask: cell.level_mask(),
        hashes: hashes.to_vec(),
        depths: depths.to_vec(),
    }
}
