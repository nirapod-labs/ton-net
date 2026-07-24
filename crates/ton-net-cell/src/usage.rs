// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Nirapod Labs

//! Recording which cells a read touches, and pruning a tree to just those.
//!
//! A Merkle proof reveals the cells a computation read and stands in for the rest. A usage
//! tree records the first half: a read marks each cell it touches, and [`prune`] then
//! rebuilds the tree with every untouched subtree replaced by a pruned branch that carries
//! only the hash and depth it stood for.
//!
//! The pruned tree hashes to the same root as the whole. A pruned branch answers at level
//! zero with the hash of the subtree it replaced, so a parent hashes the same whether it
//! holds the subtree or the branch, and that holds up to the root. Checking the pruned tree
//! against a root reached some trusted way is then what the block crate's proof engine does.
//!
//! [`prune`]: UsageTree::prune

use std::collections::HashSet;

use crate::builder::Builder;
use crate::cell::{Cell, CellType};
use crate::error::CellError;
use crate::merkle::create_proof;

mod trace;

/// The level mask of a pruned branch in a single-level proof: it stands at level one and
/// answers at level zero with the hash of what it replaced.
const PRUNED_AT_LEVEL_ONE: u8 = 0b001;

/// A record of the cells a read touched, over the tree it read.
///
/// Mark each cell as it is read, then [`prune`](UsageTree::prune) rebuilds the tree keeping
/// the marked cells and standing in for the rest. To keep a cell deep in the tree, every
/// cell on the path down to it has to be marked too, or an unmarked ancestor is pruned away
/// and takes the cell with it.
pub struct UsageTree {
    root: Cell,
    used: HashSet<[u8; 32]>,
    /// Whether a [`note`](UsageTree::note) records the cell it hands back. An explicit
    /// [`mark`](UsageTree::mark) ignores this; only the load-notification path obeys it, so
    /// a stretch of reads can be left out of the trace without losing what was marked by
    /// hand.
    tracing: bool,
}

impl UsageTree {
    /// A usage tree over `root`, with the root itself marked and tracing on.
    ///
    /// The root is always kept: a tree pruned down to nothing stands for nothing.
    #[must_use]
    pub fn new(root: Cell) -> Self {
        let mut used = HashSet::new();
        used.insert(*root.repr_hash());
        Self {
            root,
            used,
            tracing: true,
        }
    }

    /// The tree this usage was recorded over.
    #[must_use]
    pub fn root(&self) -> &Cell {
        &self.root
    }

    /// Marks `cell` as touched, so pruning keeps it.
    pub fn mark(&mut self, cell: &Cell) {
        self.used.insert(*cell.repr_hash());
    }

    /// Whether `cell` has been marked.
    #[must_use]
    pub fn touched(&self, cell: &Cell) -> bool {
        self.used.contains(cell.repr_hash())
    }

    /// Marks `cell` and every cell on the path from the root down to it.
    ///
    /// Marking a cell without its ancestors prunes an ancestor away and takes the cell with
    /// it, so keeping a deep cell means keeping its whole path. This walks the tree to find
    /// `cell`, marks the path, and reports whether the cell was there to find. It marks
    /// regardless of the tracing switch, which governs only the load-notification path.
    pub fn mark_path(&mut self, cell: &Cell) -> bool {
        let root = self.root.clone();
        mark_path_to(&root, cell.repr_hash(), &mut self.used)
    }

    /// Rebuilds the tree keeping the marked cells and standing in for the rest.
    ///
    /// Every marked cell is kept with its data intact; every subtree with nothing marked in
    /// it becomes a pruned branch carrying the hash and depth it stood for. The result reads
    /// at level zero as the same tree and hashes to the same root, with the pruned branches
    /// reading as pruned.
    ///
    /// # Errors
    ///
    /// Returns [`CellError::Malformed`] if a marked cell is exotic, which the ordinary trees
    /// a proof stands over do not hold, or if the rebuilt tree does not form.
    pub fn prune(&self) -> Result<Cell, CellError> {
        prune_cell(&self.root, &self.used)
    }

    /// Builds a Merkle proof of the marked cells over the recorded tree.
    ///
    /// This prunes the tree to the marked cells and stands the proof for the tree's root, so
    /// the proof reveals every marked cell, stands in for the rest, and verifies against the
    /// tree's own root hash. It composes [`prune`](UsageTree::prune) with proof creation.
    ///
    /// # Errors
    ///
    /// Returns [`CellError::Malformed`] if a marked cell is exotic or the tree does not
    /// rebuild.
    pub fn prove(&self) -> Result<Cell, CellError> {
        create_proof(&self.prune()?)
    }
}

/// Rebuilds `cell` against the marked set, standing in for whatever is not marked.
fn prune_cell(cell: &Cell, keep: &HashSet<[u8; 32]>) -> Result<Cell, CellError> {
    if !keep.contains(cell.repr_hash()) {
        return pruned_branch(cell);
    }
    if cell.is_exotic() {
        return Err(CellError::Malformed(
            "a proof skeleton keeps only ordinary cells",
        ));
    }

    // A kept cell keeps its own data and stands in for the children it did not keep, so its
    // level-zero hash is the one it always had and the root's hash survives the pruning.
    let mut builder = Builder::new();
    let mut bits = cell.parse();
    for _ in 0..cell.bit_len() {
        builder.store_bit(bits.load_bit()?)?;
    }
    for child in cell.refs() {
        builder.store_ref(prune_cell(child, keep)?)?;
    }
    builder.build()
}

/// A pruned branch standing in for `cell`, carrying its level-zero hash and depth.
///
/// Below its own level a pruned branch answers with what it replaced, so a parent that held
/// `cell` hashes the same whether it holds `cell` or this. That substitution is the whole of
/// how a pruned tree keeps the root of the full one.
fn pruned_branch(cell: &Cell) -> Result<Cell, CellError> {
    let mut builder = Builder::new();
    builder.store_uint(0x01, 8)?; // the pruned-branch tag
    builder.store_uint(u64::from(PRUNED_AT_LEVEL_ONE), 8)?; // the mask, carried in the data too
    builder.store_bytes(cell.hash())?;
    builder.store_uint(u64::from(cell.depth()), 16)?;
    builder.finish(CellType::PrunedBranch, PRUNED_AT_LEVEL_ONE)
}

/// Marks the path from `node` down to the cell whose hash is `target`, if it is below
/// `node`, and reports whether it was found. Every cell on the found path is marked, the
/// target and each of its ancestors, so pruning keeps the target reachable.
fn mark_path_to(node: &Cell, target: &[u8; 32], used: &mut HashSet<[u8; 32]>) -> bool {
    if node.repr_hash() == target {
        used.insert(*target);
        return true;
    }
    for child in node.refs() {
        if mark_path_to(child, target, used) {
            used.insert(*node.repr_hash());
            return true;
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::merkle::virtualize;

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

    #[test]
    fn pruning_keeps_the_root_hash() {
        let kept = leaf(0x11);
        let dropped = leaf(0x22);
        let root = node(0xaa, &[&kept, &dropped]);

        let mut usage = UsageTree::new(root.clone());
        usage.mark(&kept);
        let skeleton = usage.prune().expect("the skeleton builds");

        // The whole point: a pruned copy stands where the full tree did.
        assert_eq!(skeleton.hash(), root.hash());
    }

    #[test]
    fn an_unmarked_branch_becomes_a_pruned_branch() {
        let kept = leaf(0x11);
        let dropped = node(0x22, &[&leaf(0x33)]);
        let root = node(0xaa, &[&kept, &dropped]);

        let mut usage = UsageTree::new(root);
        usage.mark(&kept);
        let skeleton = usage.prune().expect("the skeleton builds");

        let kept_side = skeleton.reference(0).expect("the kept child is there");
        let pruned_side = skeleton.reference(1).expect("the dropped child is there");
        assert_eq!(kept_side.cell_type(), CellType::Ordinary);
        assert_eq!(pruned_side.cell_type(), CellType::PrunedBranch);
        // A pruned branch answers with the hash of the subtree it replaced.
        assert_eq!(pruned_side.hash(), dropped.hash());
        // And the kept side still reads.
        assert_eq!(kept_side.hash(), kept.hash());
    }

    #[test]
    fn a_marked_cell_deep_in_the_tree_needs_its_path_marked() {
        let deep = leaf(0x33);
        let middle = node(0x22, &[&deep]);
        let root = node(0xaa, &[&middle]);

        // Marking only the deep cell, not the node above it, prunes the node and so the
        // deep cell with it. The root hash still holds, but the deep cell is gone.
        let mut usage = UsageTree::new(root.clone());
        usage.mark(&deep);
        let skeleton = usage.prune().expect("the skeleton builds");
        assert_eq!(skeleton.hash(), root.hash());
        assert_eq!(
            skeleton
                .reference(0)
                .expect("the middle child is there")
                .cell_type(),
            CellType::PrunedBranch,
        );

        // Marking the whole path keeps the deep cell reachable.
        let mut usage = UsageTree::new(root.clone());
        usage.mark(&middle);
        usage.mark(&deep);
        let skeleton = usage.prune().expect("the skeleton builds");
        assert_eq!(skeleton.hash(), root.hash());
        let middle_side = skeleton.reference(0).expect("the middle child is there");
        assert_eq!(middle_side.cell_type(), CellType::Ordinary);
        assert_eq!(
            middle_side
                .reference(0)
                .expect("the deep child is there")
                .hash(),
            deep.hash(),
        );
    }

    #[test]
    fn a_marked_exotic_cell_is_refused() {
        // A proof stands over ordinary trees. Keeping an exotic cell has no meaning the
        // rebuild can carry, so it is refused rather than rebuilt as something it is not.
        let dropped = leaf(0x22);
        let root = node(0xaa, &[&dropped]);
        let mut usage = UsageTree::new(root.clone());
        // Mark the pruned form of a child, an exotic cell, then stand it up as the root of
        // its own usage tree to reach the guard.
        let pruned = pruned_branch(&dropped).expect("a pruned branch builds");
        let mut usage_over_exotic = UsageTree::new(pruned.clone());
        usage_over_exotic.mark(&pruned);
        assert_eq!(
            usage_over_exotic.prune(),
            Err(CellError::Malformed(
                "a proof skeleton keeps only ordinary cells"
            ))
        );
        // The ordinary tree above still prunes without complaint.
        usage.mark(&root);
        assert!(usage.prune().is_ok());
    }

    #[test]
    fn a_usage_tree_proves_the_marked_cells() {
        let kept = leaf(0x11);
        let dropped = leaf(0x22);
        let root = node(0xaa, &[&kept, &dropped]);

        let mut usage = UsageTree::new(root.clone());
        usage.mark(&kept);
        let proof = usage.prove().expect("the proof builds");

        // The proof stands for the whole tree by its root; reading back through it lands on
        // a copy that hashes to the same root with the unmarked side pruned.
        assert_eq!(proof.cell_type(), CellType::MerkleProof);
        let covered = virtualize(&proof).expect("the proof virtualizes");
        assert_eq!(covered.hash(), root.hash());
        assert_eq!(
            covered.reference(1).expect("the dropped side").cell_type(),
            CellType::PrunedBranch,
        );
    }

    #[test]
    fn mark_path_keeps_a_deep_cell_in_one_call() {
        let deep = leaf(0x33);
        let middle = node(0x22, &[&deep]);
        let root = node(0xaa, &[&middle]);

        // One call marks the whole path, where marking the deep cell alone would prune it.
        let mut usage = UsageTree::new(root.clone());
        assert!(usage.mark_path(&deep), "the deep cell is in the tree");
        let skeleton = usage.prune().expect("the skeleton builds");
        assert_eq!(skeleton.hash(), root.hash());
        let middle_side = skeleton.reference(0).expect("the middle child is there");
        assert_eq!(middle_side.cell_type(), CellType::Ordinary);
        assert_eq!(
            middle_side
                .reference(0)
                .expect("the deep child is there")
                .hash(),
            deep.hash(),
            "the deep cell survived because its path was marked",
        );
    }

    #[test]
    fn mark_path_reports_a_cell_that_is_not_in_the_tree() {
        let root = node(0xaa, &[&leaf(0x11)]);
        let stranger = leaf(0x99);
        let mut usage = UsageTree::new(root);
        assert!(!usage.mark_path(&stranger), "a stranger is not found");
    }
}
