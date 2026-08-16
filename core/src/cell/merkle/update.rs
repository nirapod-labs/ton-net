// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Nirapod Labs

//! Building and applying a Merkle update.
//!
//! A Merkle update carries two trees by hash, an old and a new, each pruned to the branches
//! that differ. Creating one wraps a pair of trees the way a proof wraps one. Applying one
//! grafts the unchanged subtrees back from a base that holds the old tree, rebuilding the new
//! tree as far as that base reaches: a whole old state gives back a whole new one, a proof
//! skeleton gives back a skeleton, and either way what comes out is held to the update's
//! stored new hash before it is returned.

use std::collections::HashMap;

use super::covering_cell;
use crate::cell::builder::Builder;
use crate::cell::cell::{Cell, CellType};
use crate::cell::error::CellError;

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
/// [`apply_update`] does not run this, and the split is deliberate. Applying holds the stored
/// old hash against the base it was handed and the stored new hash against the tree it
/// rebuilt, which is the same pair of hash equalities reached from the trees a caller
/// actually has rather than from the ones the update attached. What applying leaves unchecked
/// is the two stored depths, and a stored depth cannot reach the result: the rebuilt tree's
/// depth is the one [`Builder`] derives from the cells it was given. So an update carrying a
/// depth its own content does not give is refused here and applies all the same, which
/// `an_update_whose_stored_depth_is_wrong_still_applies` pins.
///
/// [`combine_updates`] does run this, because it reads both sides of both updates as trees
/// and re-covers them, so a side that is not the tree its update named would be carried into
/// a combined update standing for something neither input stood for.
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

/// Applies a Merkle update to the base it transforms, returning the new tree.
///
/// `base` is the old tree, the one the update's old side stands for. Where the update's new
/// side prunes a branch, that branch is an unchanged subtree, and this grafts it back from
/// `base` by its hash. The result hashes at level zero to the new hash the update names,
/// which is checked before it is returned.
///
/// The result is no more complete than `base` in the regions the update prunes, and is
/// complete in the regions the new side reveals. A base holding a pruned branch is
/// legitimate and not refused: a proof skeleton answers at level zero with the hash of the
/// subtree it stands for, so grafting from it yields a tree that hashes to the update's new
/// hash while still carrying pruned branches of its own. That is the case a caller holding a
/// state proof rather than a whole state is in, and the mainnet basechain block's own state
/// update applied to its own pruned old side is one, which
/// `applying_a_mainnet_state_update_to_a_pruned_base_keeps_the_pruning` pins. A caller that
/// needs a result it can read to the leaves supplies a base it can read to the leaves.
///
/// # Errors
///
/// Returns [`CellError::Malformed`] if `update` is not a Merkle update, if `base` is not the
/// tree its old side stands for, if a pruned branch names a subtree the base does not hold,
/// if the new side nests a Merkle cell, or if the rebuilt tree does not hash to the update's
/// new hash.
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
/// Two hash equalities bracket the work and neither is skippable: the update's stored old
/// hash against the base, before anything is walked, and its stored new hash against the tree
/// that came out. Nothing here reads the update's old side, since the base is the tree being
/// transformed and the old side is a copy of it the sender attached. [`validate_update`] is
/// the check over those attached sides and is not run here; the sentence on it says why.
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
///
/// Every cell means a pruned branch too, which is what lets a proof skeleton serve as a base:
/// a branch answers at level zero with the hash of the subtree it stands for, so it lands
/// under that subtree's key and is grafted in where the subtree would have been. The first
/// insertion for a hash wins, so where a base carries only the branch the result carries the
/// branch onward, and where it carries both the branch and the real subtree the walk decides
/// between them by which it reaches first.
fn index_by_hash(tree: &Cell, into: &mut HashMap<[u8; 32], Cell>) {
    if into.contains_key(tree.hash()) {
        return;
    }
    into.insert(*tree.hash(), tree.clone());
    for child in tree.refs() {
        index_by_hash(child, into);
    }
}

/// Rebuilds `node` against the base index, grafting each pruned branch back from it.
fn graft(node: &Cell, base: &HashMap<[u8; 32], Cell>) -> Result<Cell, CellError> {
    match node.cell_type() {
        // A pruned branch on the new side stands for a subtree that did not change, so the
        // base holds it under the hash the branch answers with.
        CellType::PrunedBranch => base.get(node.hash()).cloned().ok_or(CellError::Malformed(
            "merkle update prunes a subtree the base does not hold",
        )),
        // A library reference stands in for nothing: it names code by hash. `classify` in
        // `boc/parse.rs` holds one off the wire to zero references, so nothing read from a
        // bag carries a pruned branch under it to graft. The cell the new side
        // revealed is already the cell the new tree holds, and one sits in the state update
        // of the basechain block in `tests/fixtures/block-basechain.hex`, so refusing it
        // would refuse a state transition the network itself produced.
        CellType::LibraryReference => Ok(node.clone()),
        // A Merkle cell inside an update covers a further tree at a further level, which is
        // the running virtualization offset this module's documentation defers until a
        // structure this client reads needs one.
        CellType::MerkleProof | CellType::MerkleUpdate => Err(CellError::Malformed(
            "a merkle update rebuilds no merkle cell nested inside it",
        )),
        CellType::Ordinary => {
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
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cell::UsageTree;

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

    /// A Merkle update over `old` and `new` whose stored depths are what `depths` names
    /// rather than what the two sides give.
    ///
    /// [`create_update`] writes each side's own depth, so forging one takes the covering
    /// layout by hand. Everything else is what `covering_cell` writes: the tag, both hashes,
    /// both depths, both sides, and the mask the two sides imply.
    fn update_with_depths(old: &Cell, new: &Cell, depths: (u16, u16)) -> Cell {
        let mut builder = Builder::new();
        builder.store_uint(0x04, 8).expect("the tag fits");
        builder.store_bytes(old.hash()).expect("the old hash fits");
        builder.store_bytes(new.hash()).expect("the new hash fits");
        builder
            .store_uint(u64::from(depths.0), 16)
            .expect("a depth fits");
        builder
            .store_uint(u64::from(depths.1), 16)
            .expect("a depth fits");
        builder.store_ref(old.clone()).expect("the old side fits");
        builder.store_ref(new.clone()).expect("the new side fits");
        builder
            .finish(
                CellType::MerkleUpdate,
                (old.level_mask() | new.level_mask()) >> 1,
            )
            .expect("the update cell is well formed")
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
    fn an_update_whose_stored_depth_is_wrong_still_applies() {
        let shared = leaf(0x55);
        let old_full = node(0x11, &[&shared, &leaf(0xaa)]);
        let new_full = node(0x22, &[&shared, &leaf(0xbb)]);
        let old_side = prune_to(&old_full, &[&leaf(0xaa)]);
        let new_side = prune_to(&new_full, &[&leaf(0xbb)]);

        // Both sides are one deep. Naming the new side as seven deep leaves both stored tree
        // hashes as the sides give them, and only the stored depth wrong.
        assert_eq!(new_side.depth(), 1, "the fixture is one deep");
        let forged = update_with_depths(&old_side, &new_side, (old_side.depth(), 7));

        // The check over the attached sides catches it, and names the depth rather than a
        // hash, so this is the depth half of the split and not a hash mismatch in disguise.
        assert_eq!(
            validate_update(&forged),
            Err(CellError::Malformed(
                "merkle update depth does not match its content"
            ))
        );

        // Applying does not run that check, and cannot be misled by what it skipped: the
        // rebuilt tree is the one the update's new hash names, at the depth the rebuild
        // gives it rather than the depth the update claimed.
        let rebuilt = apply_update(&old_full, &forged).expect("the update still applies");
        assert_eq!(rebuilt.hash(), new_full.hash());
        assert_eq!(rebuilt.depth(), new_full.depth());
        assert_ne!(rebuilt.depth(), 7, "the claimed depth reached nothing");
    }

    #[test]
    fn applying_against_a_pruned_base_keeps_the_pruning() {
        let shared = leaf(0x55);
        let old_full = node(0x11, &[&shared, &leaf(0xaa)]);
        let new_full = node(0x22, &[&shared, &leaf(0xbb)]);
        let old_side = prune_to(&old_full, &[&leaf(0xaa)]);
        let new_side = prune_to(&new_full, &[&leaf(0xbb)]);
        let update = create_update(&old_side, &new_side).expect("the update builds");

        // The base here is the update's own old side, a skeleton rather than the whole old
        // tree. It answers at level zero with the same hash the whole tree does, so the
        // update applies to it.
        let rebuilt = apply_update(&old_side, &update).expect("a pruned base is not refused");
        assert_eq!(rebuilt.hash(), new_full.hash());

        // What came back stands for the new tree without holding it: the shared subtree the
        // base had already pruned is still a pruned branch.
        assert_eq!(
            rebuilt
                .reference(0)
                .expect("the shared side is there")
                .cell_type(),
            CellType::PrunedBranch,
        );
        assert_ne!(
            rebuilt.level_mask(),
            0,
            "a tree carrying a pruned branch stands above level zero"
        );
        // Against the whole old tree the same update gives back the whole new tree, which is
        // what makes the line above a property of the base and not of the update.
        let whole = apply_update(&old_full, &update).expect("the update applies");
        assert_eq!(
            whole
                .reference(0)
                .expect("the shared side is there")
                .cell_type(),
            CellType::Ordinary,
        );
        assert_eq!(whole.level_mask(), 0);
    }

    #[test]
    fn a_revealed_library_reference_is_carried_through_and_a_nested_merkle_cell_is_not() {
        // A library reference names code by hash and holds no reference, so it is content
        // the new side revealed rather than a placeholder standing for something the base
        // holds. One sits inside the state update of the basechain block fixture.
        let mut builder = Builder::new();
        builder.store_uint(0x02, 8).expect("the tag fits");
        builder.store_bytes(&[0x7c; 32]).expect("the hash fits");
        let library = builder
            .finish(CellType::LibraryReference, 0)
            .expect("a library reference is well formed");

        let old = node(0x11, &[&leaf(0xaa)]);
        let new = node(0x22, &[&library]);
        let update = create_update(&old, &new).expect("the update builds");
        let rebuilt = apply_update(&old, &update).expect("the library reference is carried");
        assert_eq!(rebuilt.hash(), new.hash());
        assert_eq!(
            rebuilt
                .reference(0)
                .expect("the library side is there")
                .cell_type(),
            CellType::LibraryReference,
        );

        // A Merkle cell nested in a side covers a further tree at a further level, which
        // this module resolves for nothing and so refuses rather than copies.
        let mut builder = Builder::new();
        builder.store_uint(0x03, 8).expect("the tag fits");
        builder
            .store_bytes(leaf(0xcc).hash())
            .expect("the hash fits");
        builder.store_uint(0, 16).expect("the depth fits");
        builder.store_ref(leaf(0xcc)).expect("the content fits");
        let nested = builder
            .finish(CellType::MerkleProof, 0)
            .expect("a merkle proof is well formed");

        let nesting = node(0x33, &[&nested]);
        let update = create_update(&old, &nesting).expect("the update builds");
        assert_eq!(
            apply_update(&old, &update),
            Err(CellError::Malformed(
                "a merkle update rebuilds no merkle cell nested inside it"
            ))
        );
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
