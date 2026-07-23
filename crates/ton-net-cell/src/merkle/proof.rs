// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Nirapod Labs

//! Building the Merkle proof that stands for a tree.
//!
//! A proof is the inverse of virtualizing one: it wraps an ordinary tree, the branches to
//! withhold already pruned, in a proof cell carrying the tree's own hash and depth. The
//! block crate's engine then accepts it against the root the tree hashes to.

use super::covering_cell;
use crate::cell::{Cell, CellType};
use crate::error::CellError;

/// Builds a Merkle proof standing for `content`.
///
/// The proof holds `content` as its one reference, with the content's own level-zero hash
/// and depth stored in its data. It is the inverse of [`virtualize`](super::virtualize):
/// virtualizing the result gives `content` back, and the block crate's proof engine accepts
/// it against the root `content` hashes to.
///
/// `content` is the tree the proof reveals, an ordinary tree with the branches to withhold
/// already replaced by pruned branches, which is what [`UsageTree::prune`] produces.
///
/// # Errors
///
/// Returns [`CellError::Malformed`] if `content` is exotic, since a proof stands for an
/// ordinary tree and wrapping a pruned branch or another proof yields a shape nothing here
/// reads, or if the proof cell does not form.
///
/// [`UsageTree::prune`]: crate::UsageTree::prune
pub fn create_proof(content: &Cell) -> Result<Cell, CellError> {
    covering_cell(CellType::MerkleProof, &[content])
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::builder::Builder;
    use crate::merkle::virtualize;

    /// An ordinary leaf cell holding one byte.
    fn leaf(byte: u64) -> Cell {
        let mut builder = Builder::new();
        builder.store_uint(byte, 8).expect("a byte fits");
        builder.build().expect("a leaf is well formed")
    }

    #[test]
    fn a_proof_built_over_content_virtualizes_back_to_it() {
        let content = leaf(0xab);
        let proof = create_proof(&content).expect("an ordinary tree is provable");
        assert_eq!(proof.cell_type(), CellType::MerkleProof);
        // Building a proof and reading back through it is the round trip: the tree the proof
        // reveals is the content it was built over.
        let covered = virtualize(&proof).expect("the built proof virtualizes");
        assert_eq!(covered.repr_hash(), content.repr_hash());
    }

    #[test]
    fn a_proof_of_a_proof_is_refused() {
        // A proof stands for an ordinary tree. Its content is exotic, so wrapping it again
        // has no reading and is refused rather than built into a shape nothing virtualizes.
        let content = leaf(0xab);
        let proof = create_proof(&content).expect("an ordinary tree is provable");
        assert_eq!(
            create_proof(&proof),
            Err(CellError::Malformed(
                "a merkle cell stands for an ordinary tree"
            ))
        );
    }
}
