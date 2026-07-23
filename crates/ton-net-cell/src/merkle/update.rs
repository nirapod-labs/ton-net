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

/// Combines two chained Merkle updates into one that carries the whole change.
///
/// Given an update from tree A to tree B and one from that same B to C, this builds the
/// update from A to C. The two must chain: the first update's new tree is the second's old
/// tree. The result stands for A by its old hash and C by its new, and applying it to a base
/// that holds A rebuilds C, the same as applying the two in turn would.
///
/// Each side of the result is one update's side with the branches the other update reveals
/// spliced back in. A subtree the first update left unchanged but the second update changed
/// has to be revealed on the combined new side, or applying against A, which never held that
/// subtree's new form, would have nothing to graft; the reverse holds for the old side.
///
/// # Errors
///
/// Returns [`CellError::Malformed`] if either input is not a Merkle update, is missing a
/// side, does not stand consistently for its own content, or if the two do not chain.
pub fn combine_updates(first: &Cell, second: &Cell) -> Result<Cell, CellError> {
    validate_update(first)?;
    validate_update(second)?;

    let missing = || CellError::Malformed("merkle update is missing a side");
    let first_old = first.reference(0).ok_or_else(missing)?;
    let first_new = first.reference(1).ok_or_else(missing)?;
    let second_old = second.reference(0).ok_or_else(missing)?;
    let second_new = second.reference(1).ok_or_else(missing)?;

    // The first update's new tree has to be the second update's old tree, or there is no B
    // in the middle for the two to meet at.
    if first_new.hash() != second_old.hash() {
        return Err(CellError::Malformed(
            "merkle updates do not chain: the first's new tree is not the second's old",
        ));
    }

    let mut first_new_revealed = HashMap::new();
    revealed_cells(first_new, &mut first_new_revealed);
    let mut second_old_revealed = HashMap::new();
    revealed_cells(second_old, &mut second_old_revealed);

    // The new side is C pruned to the second update's changes, with the branches the first
    // update revealed (changed A to B, unchanged B to C) spliced back so they are present
    // rather than grafted from A. The old side is the mirror.
    let old_side = splice_revealed(first_old, &second_old_revealed)?;
    let new_side = splice_revealed(second_new, &first_new_revealed)?;
    create_update(&old_side, &new_side)
}

/// Indexes every ordinary cell in `tree` by its level-zero hash, stopping at pruned
/// branches, which reveal nothing to splice.
fn revealed_cells(tree: &Cell, into: &mut HashMap<[u8; 32], Cell>) {
    if tree.cell_type() != CellType::Ordinary {
        return;
    }
    if into.insert(*tree.hash(), tree.clone()).is_some() {
        return;
    }
    for child in tree.refs() {
        revealed_cells(child, into);
    }
}

/// Rebuilds `node`, replacing each pruned branch that `revealed` shows with the revealed
/// subtree, so a branch the other update changed is present rather than left as a
/// placeholder.
fn splice_revealed(node: &Cell, revealed: &HashMap<[u8; 32], Cell>) -> Result<Cell, CellError> {
    match node.cell_type() {
        CellType::PrunedBranch => Ok(revealed
            .get(node.hash())
            .cloned()
            .unwrap_or_else(|| node.clone())),
        CellType::Ordinary => {
            let mut builder = Builder::new();
            let mut bits = node.parse();
            for _ in 0..node.bit_len() {
                builder.store_bit(bits.load_bit()?)?;
            }
            for child in node.refs() {
                builder.store_ref(splice_revealed(child, revealed)?)?;
            }
            builder.build()
        }
        _ => Err(CellError::Malformed(
            "combining a merkle update over an unexpected exotic cell",
        )),
    }
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

    #[test]
    fn combining_two_updates_rebuilds_the_far_tree() {
        let shared = leaf(0x55); // unchanged through both steps
        let a1 = leaf(0xa1);
        let b1 = leaf(0xb1); // a1 becomes b1 from A to B, then holds through C
        let a2 = leaf(0xa2); // holds from A to B, then becomes c2 from B to C
        let c2 = leaf(0xc2);

        let a = node(0x01, &[&shared, &a1, &a2]);
        let b = node(0x02, &[&shared, &b1, &a2]);
        let c = node(0x03, &[&shared, &b1, &c2]);

        // Each update reveals what changed at its step and prunes the rest.
        let u1 = create_update(&prune_to(&a, &[&a1]), &prune_to(&b, &[&b1])).expect("u1 builds");
        let u2 = create_update(&prune_to(&b, &[&a2]), &prune_to(&c, &[&c2])).expect("u2 builds");

        let combined = combine_updates(&u1, &u2).expect("the updates combine");
        validate_update(&combined).expect("the combined update is consistent");

        // The combined update rebuilds C from A in one step, the same as the two in turn.
        let one_step = apply_update(&a, &combined).expect("the combined update applies");
        assert_eq!(one_step.hash(), c.hash());
        let two_steps = apply_update(&apply_update(&a, &u1).unwrap(), &u2).expect("u2 applies");
        assert_eq!(two_steps.hash(), c.hash(), "the two applied in turn agree");
    }

    #[test]
    fn updates_that_do_not_chain_are_refused() {
        let u1 = create_update(&leaf(0x11), &leaf(0x22)).expect("u1 builds");
        let u2 = create_update(&leaf(0x33), &leaf(0x44)).expect("u2 builds");
        // The first update's new tree, 0x22, is not the second's old tree, 0x33.
        assert!(matches!(
            combine_updates(&u1, &u2),
            Err(CellError::Malformed(_))
        ));
    }
}
