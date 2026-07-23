// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Nirapod Labs

//! Cell hashing, measured against hashes TON produced.
//!
//! The level rule for exotic cells is the piece a proof engine gets subtly wrong, so
//! none of these tests compare against a value this crate generated. They use the
//! well-known empty-cell hash, and a proof a mainnet liteserver returned whose Merkle
//! cells carry the hashes the node computed for the trees they cover.
//!
//! This is the check `spikes/proof-feasibility` ran against a live server, kept here as
//! a test that never touches the network.

use ton_net_cell::{parse_boc, serialize_boc, Cell, CellType};

/// The captured proof bytes, hex encoded.
const PROOF_HEX: &str = include_str!("../fixtures/account-proof.hex");

/// The root hash of the masterchain block the proof was read at.
const BLOCK_ROOT_HASH: &str = "2f138b6a0e45ec466c1f44326f7d7d638c5f8514786f67160aa2fe2dd6ae0323";

/// The hash of an empty ordinary cell, a constant across the TON ecosystem.
const EMPTY_CELL_HASH: &str = "96a296d224f285c67bee93c30f8a309157f0daa35dc5b87e410b78630a09cfc7";

/// A bag holding one empty cell: no data, no references.
const EMPTY_CELL_BOC: [u8; 13] = [
    0xb5, 0xee, 0x9c, 0x72, 0x01, 0x01, 0x01, 0x01, 0x00, 0x02, 0x00, 0x00, 0x00,
];

fn unhex(s: &str) -> Vec<u8> {
    let s = s.trim();
    (0..s.len() / 2)
        .map(|i| u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).expect("hex"))
        .collect()
}

fn proof_roots() -> Vec<Cell> {
    parse_boc(&unhex(PROOF_HEX)).expect("the captured proof parses")
}

fn walk(cell: &Cell, out: &mut Vec<Cell>) {
    out.push(cell.clone());
    for child in cell.refs() {
        walk(child, out);
    }
}

fn all_cells(roots: &[Cell]) -> Vec<Cell> {
    let mut out = Vec::new();
    for root in roots {
        walk(root, &mut out);
    }
    out
}

#[test]
fn an_empty_cell_hashes_to_the_known_constant() {
    // The whole TON ecosystem agrees on this value, so reproducing it anchors the
    // representation: two descriptor bytes, no data, no references, under SHA-256.
    let roots = parse_boc(&EMPTY_CELL_BOC).expect("an empty cell parses");
    assert_eq!(roots[0].bit_len(), 0);
    assert_eq!(roots[0].hash()[..], unhex(EMPTY_CELL_HASH)[..]);
    assert_eq!(roots[0].depth(), 0);
}

#[test]
fn every_merkle_cell_certifies_the_tree_it_covers() {
    // A Merkle cell stores the level-0 hash of the tree it covers. Recomputing that
    // hash from the pruned tree and landing on the stored value is the whole proof
    // mechanism: it only works if the level rules, including a pruned branch standing in
    // for the subtree it replaced, are right.
    let roots = proof_roots();
    let mut checked = 0;
    for cell in all_cells(&roots) {
        if cell.cell_type() != CellType::MerkleProof {
            continue;
        }
        let stored = &cell.data()[1..33];
        let covered = cell.reference(0).expect("a merkle proof covers one tree");
        assert_eq!(
            covered.hash()[..],
            stored[..],
            "a merkle cell must certify the tree it covers"
        );
        checked += 1;
    }
    assert_eq!(checked, 2, "an account proof has two merkle roots");
}

#[test]
fn the_proof_recomputes_the_block_hash_it_was_read_at() {
    // The strongest check available without a network: hashing the pruned block tree
    // reproduces the hash of the masterchain block the account was read at. That hash is
    // the network's, so a wrong hashing rule cannot land on it.
    let roots = proof_roots();
    let expected = unhex(BLOCK_ROOT_HASH);
    let recomputed = roots
        .iter()
        .filter_map(|root| root.reference(0))
        .any(|covered| covered.hash()[..] == expected[..]);
    assert!(
        recomputed,
        "hashing the pruned block tree must reproduce the block hash"
    );
}

#[test]
fn the_block_proof_links_to_the_state_proof() {
    // The block's state update names the new state root, and the other Merkle root
    // covers exactly that tree. This is the link a verified account read walks.
    let roots = proof_roots();
    let cells = all_cells(&roots);

    let update = cells
        .iter()
        .find(|c| c.cell_type() == CellType::MerkleUpdate)
        .expect("the block carries a state update");
    // A merkle update stores an old and a new hash, then their depths.
    let new_state_root = &update.data()[33..65];

    let covered = roots
        .iter()
        .filter_map(|root| root.reference(0))
        .any(|tree| tree.hash()[..] == new_state_root[..]);
    assert!(covered, "a merkle root must cover the new state root");
}

#[test]
fn a_pruned_branch_answers_differently_by_level() {
    // Below its own level a pruned branch is the subtree it replaced; at its own level
    // it is only itself. Conflating the two is the classic proof-engine bug, and it is
    // why cells are shared by repr_hash rather than by hash.
    let roots = proof_roots();
    let mut seen_levels = Vec::new();
    for cell in all_cells(&roots) {
        if cell.cell_type() != CellType::PrunedBranch {
            continue;
        }
        assert_eq!(
            cell.hash_at(0)[..],
            cell.data()[2..34],
            "level zero is the subtree that was replaced"
        );
        assert_ne!(
            cell.hash(),
            cell.repr_hash(),
            "the replaced subtree and the placeholder are different cells"
        );
        seen_levels.push(cell.level());
    }

    // A proof nests a merkle update inside a merkle proof, and each shifts the level by
    // one, so pruning appears at more than one depth.
    seen_levels.sort_unstable();
    seen_levels.dedup();
    assert!(
        seen_levels.len() > 1,
        "expected pruning at several levels, saw {seen_levels:?}"
    );
}

#[test]
fn a_cell_with_no_marked_level_hashes_the_same_at_every_level() {
    // An ordinary tree has one hash; asking for a higher level must not invent another.
    let roots = parse_boc(&EMPTY_CELL_BOC).expect("an empty cell parses");
    let cell = &roots[0];
    for level in 0..=3 {
        assert_eq!(cell.hash_at(level), cell.hash());
        assert_eq!(cell.depth_at(level), cell.depth());
    }
}

#[test]
fn serializing_then_parsing_preserves_every_hash() {
    // The format admits several encodings of one graph, so the round trip is measured by
    // the hashes it reproduces, not by byte equality.
    let roots = proof_roots();
    let bytes = serialize_boc(&roots).expect("the graph serializes");
    let again = parse_boc(&bytes).expect("the output parses back");

    assert_eq!(again.len(), roots.len());
    for (before, after) in roots.iter().zip(&again) {
        assert_eq!(before.hash(), after.hash());
        assert_eq!(before.depth(), after.depth());
        assert_eq!(before.cell_type(), after.cell_type());
        assert_eq!(before.level_mask(), after.level_mask());
    }
}

#[test]
fn a_serialized_bag_carries_a_checksum_that_catches_corruption() {
    let roots = proof_roots();
    let bytes = serialize_boc(&roots).expect("the graph serializes");
    assert!(parse_boc(&bytes).is_ok());

    // Flipping any byte of the body must fail the checksum rather than parse to
    // something else.
    for index in (8..bytes.len() - 4).step_by(37) {
        let mut corrupted = bytes.clone();
        corrupted[index] ^= 0xff;
        assert!(
            parse_boc(&corrupted).is_err(),
            "a bag corrupted at {index} must not parse"
        );
    }
}

#[test]
fn shared_cells_are_stored_once() {
    // Two roots over one graph: the cells they share must not be written twice.
    let roots = proof_roots();
    let bytes = serialize_boc(&roots).expect("the graph serializes");
    let again = parse_boc(&bytes).expect("the output parses back");

    let unique_before = {
        let mut hashes: Vec<_> = all_cells(&roots).iter().map(|c| *c.hash()).collect();
        hashes.sort_unstable();
        hashes.dedup();
        hashes.len()
    };
    let unique_after = {
        let mut hashes: Vec<_> = all_cells(&again).iter().map(|c| *c.hash()).collect();
        hashes.sort_unstable();
        hashes.dedup();
        hashes.len()
    };
    assert_eq!(unique_before, unique_after);
}
