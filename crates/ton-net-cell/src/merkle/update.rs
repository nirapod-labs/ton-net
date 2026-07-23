// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Nirapod Labs

//! Building and applying a Merkle update.
//!
//! A Merkle update carries two trees by hash, an old and a new, each pruned to the branches
//! that differ. Creating one wraps a pair of trees the way a proof wraps one. Applying one
//! grafts the unchanged subtrees back from a base that holds the old tree, rebuilding the
//! new tree whole.

use std::collections::HashMap;

use super::covering_cell;
use crate::builder::Builder;
use crate::cell::{Cell, CellType};
use crate::error::CellError;

/// The offset of a Merkle update's old-tree hash within its data, past the type byte.
const OLD_HASH: usize = 1;

/// The offset of the new-tree hash, past the old one.
const NEW_HASH: usize = OLD_HASH + 32;

/// The offset of the old-tree depth, past both hashes.
const OLD_DEPTH: usize = NEW_HASH + 32;

/// The offset of the new-tree depth, past the old one.
const NEW_DEPTH: usize = OLD_DEPTH + 2;

/// Builds a Merkle update from an old tree to a new one.
///
/// Each side is an ordinary tree with the branches that did not change already replaced by
/// pruned branches, so the update carries only what differs. The result stands for the old
/// tree by one hash and the new by another, and [`apply_update`] rebuilds the new tree from
/// a base that holds the old.
///
/// # Errors
///
/// Returns [`CellError::Malformed`] if either side is exotic, or the cell does not form.
pub fn create_update(old: &Cell, new: &Cell) -> Result<Cell, CellError> {
    covering_cell(CellType::MerkleUpdate, &[old, new])
}

/// Checks a Merkle update stands consistently for the two trees attached to it.
///
/// Each side's stored hash and depth have to be the ones the tree attached gives, the same
/// self-consistency [`virtualize`](super::virtualize) requires of a proof. This does not
/// anchor either side to a trusted root; it checks the update against itself.
///
/// # Errors
///
/// Returns [`CellError::Malformed`] if `update` is not a Merkle update, is missing a side,
/// or stores a hash or depth a side does not give.
pub fn validate_update(update: &Cell) -> Result<(), CellError> {
    if update.cell_type() != CellType::MerkleUpdate {
        return Err(CellError::Malformed("not a merkle update"));
    }
    let data = update.data();
    for (side, hash_at, depth_at) in [(0usize, OLD_HASH, OLD_DEPTH), (1, NEW_HASH, NEW_DEPTH)] {
        let content = update
            .reference(side)
            .ok_or(CellError::Malformed("merkle update is missing a side"))?;
        let stored_hash = data
            .get(hash_at..hash_at + 32)
            .ok_or(CellError::Malformed("merkle update has no hash"))?;
        if stored_hash != content.hash() {
            return Err(CellError::Malformed(
                "merkle update does not stand for its content",
            ));
        }
        let stored_depth: [u8; 2] = data
            .get(depth_at..depth_at + 2)
            .and_then(|bytes| bytes.try_into().ok())
            .ok_or(CellError::Malformed("merkle update has no depth"))?;
        if u16::from_be_bytes(stored_depth) != content.depth() {
            return Err(CellError::Malformed(
                "merkle update depth does not match its content",
            ));
        }
    }
    Ok(())
}

/// Applies a Merkle update to the base it transforms, returning the new tree whole.
///
/// `base` is the full old tree, the one the update's old side stands for. Where the update's
/// new side prunes a branch, that branch is an unchanged subtree, and this grafts it back
/// from `base` by its hash. The result is the new tree in full, and it hashes to the new
/// hash the update names.
///
/// # Errors
///
/// Returns [`CellError::Malformed`] if `update` is not a Merkle update, if `base` is not the
/// tree its old side stands for, if a pruned branch names a subtree the base does not hold,
/// or if the rebuilt tree does not hash to the update's new hash.
pub fn apply_update(base: &Cell, update: &Cell) -> Result<Cell, CellError> {
    may_apply(base, update)?.ok_or(CellError::Malformed(
        "merkle update does not apply to this base",
    ))
}

/// Applies a Merkle update if `base` is the tree it transforms, otherwise returns `None`.
///
/// This is [`apply_update`] without the requirement that the base matches: a base that is
/// not the update's old tree yields `None` rather than an error, which lets a caller try an
/// update against a base it is unsure of.
///
/// # Errors
///
/// Returns [`CellError::Malformed`] as [`apply_update`] does, except for the base mismatch
/// it reports as `None`.
pub fn may_apply(base: &Cell, update: &Cell) -> Result<Option<Cell>, CellError> {
    if update.cell_type() != CellType::MerkleUpdate {
        return Err(CellError::Malformed("only a merkle update can be applied"));
    }
    let data = update.data();
    let stored_old = data
        .get(OLD_HASH..OLD_HASH + 32)
        .ok_or(CellError::Malformed("merkle update has no old hash"))?;
    if stored_old != base.hash() {
        return Ok(None);
    }
    let new = update
        .reference(1)
        .ok_or(CellError::Malformed("merkle update has no new side"))?;

    let mut index = HashMap::new();
    index_by_hash(base, &mut index);
    let rebuilt = graft(new, &index)?;

    let stored_new = data
        .get(NEW_HASH..NEW_HASH + 32)
        .ok_or(CellError::Malformed("merkle update has no new hash"))?;
    if stored_new != rebuilt.hash() {
        return Err(CellError::Malformed(
            "merkle update did not rebuild its new hash",
        ));
    }
    Ok(Some(rebuilt))
}

/// Indexes every cell in `tree` by its level-zero hash.
fn index_by_hash(tree: &Cell, into: &mut HashMap<[u8; 32], Cell>) {
    if into.contains_key(tree.hash()) {
        return;
    }
    into.insert(*tree.hash(), tree.clone());
    for child in tree.refs() {
        index_by_hash(child, into);
    }
}

/// Rebuilds `node` in full, grafting each pruned branch back from the base index.
fn graft(node: &Cell, base: &HashMap<[u8; 32], Cell>) -> Result<Cell, CellError> {
    if node.cell_type() == CellType::PrunedBranch {
        // A pruned branch on the new side stands for a subtree that did not change, so the
        // base holds it under the hash the branch answers with.
        return base.get(node.hash()).cloned().ok_or(CellError::Malformed(
            "merkle update prunes a subtree the base does not hold",
        ));
    }
    if node.is_exotic() {
        return Err(CellError::Malformed(
            "a merkle update rebuilds only ordinary cells",
        ));
    }

    let mut builder = Builder::new();
    let mut bits = node.parse();
    for _ in 0..node.bit_len() {
        builder.store_bit(bits.load_bit()?)?;
    }
    for child in node.refs() {
        builder.store_ref(graft(child, base)?)?;
    }
    builder.build()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::UsageTree;

    /// An ordinary leaf cell holding one byte.
    fn leaf(byte: u64) -> Cell {
        let mut builder = Builder::new();
        builder.store_uint(byte, 8).expect("a byte fits");
        builder.build().expect("a leaf is well formed")
    }

    /// An ordinary cell holding `byte` and the given children.
    fn node(byte: u64, children: &[&Cell]) -> Cell {
        let mut builder = Builder::new();
        builder.store_uint(byte, 8).expect("a byte fits");
        for &child in children {
            builder.store_ref(child.clone()).expect("a reference fits");
        }
        builder.build().expect("a node is well formed")
    }

    /// `full` with `keep` marked and every other subtree pruned to a branch.
    fn prune_to(full: &Cell, keep: &[&Cell]) -> Cell {
        let mut usage = UsageTree::new(full.clone());
        for &cell in keep {
            usage.mark(cell);
        }
        usage.prune().expect("the side prunes")
    }

    #[test]
    fn a_built_update_validates() {
        let old = leaf(0x11);
        let new = leaf(0x22);
        let update = create_update(&old, &new).expect("the update builds");
        assert_eq!(update.cell_type(), CellType::MerkleUpdate);
        validate_update(&update).expect("a built update validates");
    }

    #[test]
    fn applying_an_update_rebuilds_the_new_tree() {
        let shared = leaf(0x55);
        let old_full = node(0x11, &[&shared, &leaf(0xaa)]);
        let new_full = node(0x22, &[&shared, &leaf(0xbb)]);

        // Each side keeps its own root and changed child, and prunes the shared subtree.
        let old_side = prune_to(&old_full, &[&leaf(0xaa)]);
        let new_side = prune_to(&new_full, &[&leaf(0xbb)]);
        let update = create_update(&old_side, &new_side).expect("the update builds");

        // Applying it against the full old tree grafts the shared subtree back and rebuilds
        // the new tree, which hashes to what the update named.
        let rebuilt = apply_update(&old_full, &update).expect("the update applies");
        assert_eq!(rebuilt.hash(), new_full.hash());
    }

    #[test]
    fn an_update_does_not_apply_to_the_wrong_base() {
        let update = create_update(&leaf(0x11), &leaf(0x22)).expect("the update builds");
        // A base that is not the old tree is not one this update transforms.
        assert!(may_apply(&leaf(0x99), &update)
            .expect("a mismatch is not an error")
            .is_none());
    }
}
