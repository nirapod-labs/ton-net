// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Nirapod Labs

//! Building a Merkle proof and checking it in the block engine.
//!
//! The gate: a proof built by the cell crate has to pass the same engine that checks a
//! liteserver's. The tree is a real masterchain block, reached by virtualizing a proof a
//! mainnet liteserver actually returned, rooted at a block hash confirmed against a public
//! API independent of that server before it was pinned. A proof built here over that tree,
//! pruned to a path, verifies against the confirmed hash; a proof built for any other root
//! is refused.

use ton_net_block::proof::verify_merkle_proof;
use ton_net_block::BlockError;
use ton_net_cell::{parse_boc, virtualize, Cell, CellType, UsageTree};

/// A captured masterchain account read: a confirmed block hash and the liteserver's proof.
const MASTERCHAIN: &str = include_str!("fixtures/read-masterchain.txt");

/// Reads a `name=value` field out of a capture fixture.
fn field<'a>(text: &'a str, name: &str) -> &'a str {
    text.lines()
        .find_map(|line| line.strip_prefix(name)?.strip_prefix('='))
        .expect("the field is present")
        .trim()
}

/// Decodes a hex string into bytes.
fn unhex(hex: &str) -> Vec<u8> {
    (0..hex.len() / 2)
        .map(|i| u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).expect("hex"))
        .collect()
}

/// Reads a 32-byte hash out of a hex field.
fn read_hash(hex: &str) -> [u8; 32] {
    unhex(hex).try_into().expect("a 32-byte hash")
}

/// The block tree the liteserver's proof stands for, with the confirmed hash it roots at.
fn covered_block() -> (Cell, [u8; 32]) {
    let block_hash = read_hash(field(MASTERCHAIN, "block_root_hash"));
    let roots = parse_boc(&unhex(field(MASTERCHAIN, "proof"))).expect("the proof parses");
    for root in &roots {
        if root.cell_type() != CellType::MerkleProof {
            continue;
        }
        if root.data().get(1..33) != Some(&block_hash[..]) {
            continue;
        }
        let covered = virtualize(root).expect("the block proof virtualizes");
        assert_eq!(
            covered.hash(),
            &block_hash,
            "the tree roots at the block hash"
        );
        return (covered, block_hash);
    }
    panic!("no proof in the bag roots at the block hash");
}

#[test]
fn a_proof_built_here_verifies_against_the_confirmed_block_hash() {
    let (block, block_hash) = covered_block();

    // Record a path into the block and prune to it. The pruned tree stands in for every
    // branch off that path and still hashes to the block hash, because a kept cell keeps its
    // own level-zero hash.
    let mut usage = UsageTree::new(block.clone());
    let info = block.reference(0).expect("a block holds a first reference");
    usage.mark(info);
    let proof = usage.prove().expect("the proof builds");

    // The engine that checks a liteserver's proof accepts this one, against a hash confirmed
    // outside the server that sent the tree.
    let covered = verify_merkle_proof(&proof, &block_hash).expect("the built proof verifies");
    assert_eq!(covered.hash(), &block_hash);
    assert_eq!(
        covered
            .reference(0)
            .expect("the marked path is kept")
            .cell_type(),
        CellType::Ordinary,
        "the marked path reads as ordinary through the proof",
    );
}

#[test]
fn a_proof_does_not_verify_against_another_root() {
    let (block, block_hash) = covered_block();
    let proof = UsageTree::new(block).prove().expect("the proof builds");

    let mut other = block_hash;
    other[0] ^= 1;
    // A proof stands for one tree. Checked against any other root it is refused, which is
    // what stops a proof of one block from answering for another.
    assert!(matches!(
        verify_merkle_proof(&proof, &other),
        Err(BlockError::ProofNotAnchored)
    ));
}
