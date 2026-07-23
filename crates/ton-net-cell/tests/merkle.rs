// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Nirapod Labs

//! Virtualizing real mainnet Merkle proofs.
//!
//! The account proof captured from a liteserver is a bag of Merkle proofs. Virtualizing
//! each one reads back the tree it stands for, and that tree has to hash to the root the
//! proof claims. One of the proofs stands for a block whose hash was recorded when the bag
//! was captured, so the read is tied to a value from outside the proof rather than to the
//! proof's own arithmetic alone.

use ton_net_cell::{parse_boc, virtualize, CellType};

/// The account proof captured from mainnet, a bag of Merkle proofs.
const ACCOUNT_PROOF: &str = include_str!("fixtures/account-proof.hex");

/// The masterchain block hash the bag was captured under. One proof stands for it.
const PROOF_BLOCK_HASH: &str = "2f138b6a0e45ec466c1f44326f7d7d638c5f8514786f67160aa2fe2dd6ae0323";

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
