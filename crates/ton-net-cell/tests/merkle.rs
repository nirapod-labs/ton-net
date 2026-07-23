// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Nirapod Labs

//! Reading mainnet Merkle proofs, and pruning mainnet trees to proof skeletons.
//!
//! The account proof captured from a liteserver is a bag of Merkle proofs. Virtualizing
//! each one reads back the tree it stands for, and that tree has to hash to the root the
//! proof claims. One of the proofs stands for a block whose hash was recorded when the bag
//! was captured, so the read is tied to a value from outside the proof rather than to the
//! proof's own arithmetic alone.
//!
//! Pruning runs the other way: a whole block is recorded down to one path and rebuilt with
//! the rest stood in for, and the pruned block still hashes to the identity it was served
//! under. That is the property a Merkle proof rests on, held to real bytes.

use ton_net_cell::{parse_boc, virtualize, CellType, UsageTree};

/// The account proof captured from mainnet, a bag of Merkle proofs.
const ACCOUNT_PROOF: &str = include_str!("fixtures/account-proof.hex");

/// The masterchain block hash the bag was captured under. One proof stands for it.
const PROOF_BLOCK_HASH: &str = "2f138b6a0e45ec466c1f44326f7d7d638c5f8514786f67160aa2fe2dd6ae0323";

/// A whole basechain block, and the root hash the liteserver served it under.
const BASECHAIN_BLOCK: &str = include_str!("fixtures/block-basechain.hex");
const BASECHAIN_ROOT: &str = "80cbafe6a27bb13ff6f7aa1a103d8a30989fba77c737457160b372359fcf5696";

/// Decodes a hex-dump fixture into bytes, skipping `#` comment lines and whitespace.
fn unhex(text: &str) -> Vec<u8> {
    let hex: String = text
        .lines()
        .filter(|line| !line.starts_with('#'))
        .flat_map(str::chars)
        .filter(|c| !c.is_whitespace())
        .collect();
    (0..hex.len() / 2)
        .map(|i| u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).expect("hex"))
        .collect()
}

/// Renders bytes as lowercase hex.
fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    bytes.iter().fold(String::new(), |mut out, b| {
        let _ = write!(out, "{b:02x}");
        out
    })
}

#[test]
fn every_mainnet_proof_virtualizes_to_the_tree_it_stands_for() {
    let roots = parse_boc(&unhex(ACCOUNT_PROOF)).expect("the proof parses");
    let mut proofs = 0usize;
    for root in &roots {
        if root.cell_type() != CellType::MerkleProof {
            continue;
        }
        proofs += 1;
        let covered = virtualize(root).expect("a mainnet proof virtualizes");
        // What a proof stands for reads at level zero as the tree it covers, and a block
        // and a state are ordinary cells with the pruned branches hanging off them below.
        assert_eq!(covered.cell_type(), CellType::Ordinary);
        assert!(
            !covered.refs().is_empty(),
            "the covered tree is a single leaf, not a block or a state"
        );
    }
    assert!(proofs >= 1, "the bag holds no merkle proofs to virtualize");
}

#[test]
fn a_proof_stands_for_the_block_the_bag_was_captured_under() {
    let roots = parse_boc(&unhex(ACCOUNT_PROOF)).expect("the proof parses");

    // The block hash was the liteserver's answer at capture time, so it is a fact from
    // outside the proof bytes. Reading through the proof that claims it must yield a tree
    // that hashes back to the same value.
    let mut found = false;
    for root in &roots {
        if root.cell_type() != CellType::MerkleProof {
            continue;
        }
        if hex(&root.data()[1..33]) != PROOF_BLOCK_HASH {
            continue;
        }
        found = true;
        let covered = virtualize(root).expect("the block proof virtualizes");
        assert_eq!(hex(covered.hash()), PROOF_BLOCK_HASH);
    }
    assert!(found, "no proof stands for the captured block hash");
}

#[test]
fn pruning_a_mainnet_block_to_a_path_keeps_its_root_hash() {
    let roots = parse_boc(&unhex(BASECHAIN_BLOCK)).expect("the block parses");
    let block = &roots[0];
    assert_eq!(
        hex(block.hash()),
        BASECHAIN_ROOT,
        "the fixture is the block"
    );

    // Keep the path to the block's info, standing in for the value flow, the state update
    // and the extra. A `block` holds those four in order, so marking the root and its first
    // reference is a one-hop proof of the info against the block hash.
    let info = block.reference(0).expect("a block holds an info reference");
    let mut usage = UsageTree::new(block.clone());
    usage.mark(info);
    let skeleton = usage.prune().expect("the skeleton builds");

    assert_eq!(
        hex(skeleton.hash()),
        BASECHAIN_ROOT,
        "the pruned block does not hash to the block it was pruned from"
    );
    assert_eq!(
        skeleton.reference(0).expect("info is kept").cell_type(),
        CellType::Ordinary,
        "the kept path should read as ordinary"
    );
    for side in 1..4 {
        assert_eq!(
            skeleton
                .reference(side)
                .expect("a stood-in reference")
                .cell_type(),
            CellType::PrunedBranch,
            "reference {side} should be pruned"
        );
    }
}
