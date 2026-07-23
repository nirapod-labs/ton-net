// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Nirapod Labs

//! Reading the tree a Merkle proof stands for.
//!
//! A Merkle proof is a cell that covers one tree by hash. Its single reference holds a
//! copy of that tree with the branches the proof leaves out replaced by pruned branches,
//! and its data carries the hash and depth of the tree the copy stands for. Reading
//! through the proof to that copy is virtualization.
//!
//! The cell model already carries the arithmetic this needs. A Merkle cell resolves one
//! level of what it covers, so its content sits one level down and answers one level up,
//! which [`Cell`] computes when it is built. Virtualizing a single proof is therefore
//! taking its content and requiring the proof's stored hash and depth to be the ones that
//! content gives.
//!
//! A running virtualization offset, for reading through proofs nested inside proofs, is
//! not built here. The structures this client reads do not nest one: a block, a state, an
//! account and a shard proof each cover a single tree, and a block's state update covers a
//! pair of them at one level. The offset is added when a structure that needs it does.

use crate::cell::{Cell, CellType};
use crate::error::CellError;

/// The offset of a Merkle proof's covered root hash within its data, past the type byte.
const COVERED_HASH: usize = 1;

/// The offset of a Merkle proof's covered depth within its data, past the root hash.
const COVERED_DEPTH: usize = COVERED_HASH + 32;

/// Reads the tree a Merkle proof stands for.
///
/// The returned cell is the proof's content, which reads at level zero as the tree the
/// proof covers: where the proof keeps a branch the content holds it, and where the proof
/// leaves one out the content holds a pruned branch that reads as pruned. The branches
/// that survive are the ones the proof chose to reveal.
///
/// This does not anchor the proof to a root the caller trusts. It requires only that the
/// proof is consistent with itself, that the content attached hashes to the root and depth
/// the proof claims for it. Content read this way still has to have its hash checked
/// against a root reached some trusted way, which is what `verify_merkle_proof` in the
/// block crate adds on top.
///
/// # Errors
///
/// Returns [`CellError::Malformed`] if `proof` is not a Merkle proof, holds no content, or
/// claims a root hash or depth its content does not give.
pub fn virtualize(proof: &Cell) -> Result<Cell, CellError> {
    if proof.cell_type() != CellType::MerkleProof {
        return Err(CellError::Malformed(
            "only a merkle proof can be virtualized",
        ));
    }
    let content = proof
        .reference(0)
        .ok_or(CellError::Malformed("merkle proof holds no content"))?;

    // The proof's data carries the hash and depth of the tree it stands for. Both are a
    // claim until the content attached is hashed against them: a proof whose stored root
    // disagrees with its own content was written by a sender computing a tree this crate
    // did not, and there is no reading of it worth returning.
    let data = proof.data();
    let claimed_hash = data
        .get(COVERED_HASH..COVERED_HASH + 32)
        .ok_or(CellError::Malformed("merkle proof has no root hash"))?;
    if claimed_hash != content.hash() {
        return Err(CellError::Malformed(
            "merkle proof does not stand for its content",
        ));
    }
    let claimed_depth: [u8; 2] = data
        .get(COVERED_DEPTH..COVERED_DEPTH + 2)
        .and_then(|bytes| bytes.try_into().ok())
        .ok_or(CellError::Malformed("merkle proof has no depth"))?;
    if u16::from_be_bytes(claimed_depth) != content.depth() {
        return Err(CellError::Malformed(
            "merkle proof depth does not match its content",
        ));
    }

    Ok(content.clone())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::builder::Builder;

    /// A Merkle proof cell over `content`, claiming `hash` and `depth` for the tree it
    /// stands for.
    ///
    /// A well-formed proof claims the content's own hash and depth. Passing anything else
    /// is how the tests below forge one, since the cell model builds the proof cell without
    /// checking that its stored root is the one its content gives.
    fn merkle_over(content: &Cell, hash: &[u8; 32], depth: u16) -> Cell {
        let mut builder = Builder::new();
        builder.store_uint(0x03, 8).expect("the tag fits");
        builder.store_bytes(hash).expect("the hash fits");
        builder
            .store_uint(u64::from(depth), 16)
            .expect("the depth fits");
        builder
            .store_ref(content.clone())
            .expect("one reference fits");
        builder
            .finish(CellType::MerkleProof, content.level_mask() >> 1)
            .expect("the proof cell is well formed")
    }

    /// An ordinary leaf cell holding one byte.
    fn leaf(byte: u64) -> Cell {
        let mut builder = Builder::new();
        builder.store_uint(byte, 8).expect("a byte fits");
        builder.build().expect("a leaf is well formed")
    }

    #[test]
    fn a_proof_virtualizes_to_the_content_it_stands_for() {
        let content = leaf(0xab);
        let proof = merkle_over(&content, content.hash(), content.depth());
        let covered = virtualize(&proof).expect("a well-formed proof virtualizes");
        assert_eq!(covered.repr_hash(), content.repr_hash());
    }

    #[test]
    fn only_a_merkle_proof_virtualizes() {
        // An ordinary cell is a tree, not a proof of one. Reading through it is a mistake
        // the caller should hear about rather than have quietly handed back.
        assert_eq!(
            virtualize(&leaf(0xab)),
            Err(CellError::Malformed(
                "only a merkle proof can be virtualized"
            ))
        );
    }

    #[test]
    fn a_proof_that_claims_a_hash_its_content_does_not_give_is_refused() {
        let content = leaf(0xab);
        let mut wrong = *content.hash();
        wrong[0] ^= 1;
        let forged = merkle_over(&content, &wrong, content.depth());
        assert_eq!(
            virtualize(&forged),
            Err(CellError::Malformed(
                "merkle proof does not stand for its content"
            ))
        );
    }

    #[test]
    fn a_proof_that_claims_a_depth_its_content_does_not_give_is_refused() {
        let content = leaf(0xab);
        let forged = merkle_over(&content, content.hash(), content.depth() + 1);
        assert_eq!(
            virtualize(&forged),
            Err(CellError::Malformed(
                "merkle proof depth does not match its content"
            ))
        );
    }
}
