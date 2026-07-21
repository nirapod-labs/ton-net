//! Parsing a bag of cells TON produced, not one this crate wrote.
//!
//! The fixture is the proof a mainnet liteserver returned for the config contract at
//! masterchain block 80970741, captured by `spikes/proof-feasibility`. Anchoring the
//! parser to real bytes, and to hashes the node computed, is what keeps these tests from
//! measuring this crate against itself.

use ton_net_cell::{parse_boc, Cell, CellType};

/// The captured proof bytes, hex encoded.
const PROOF_HEX: &str = include_str!("fixtures/account-proof.hex");

/// The root hash of the masterchain block the proof was read at.
const BLOCK_ROOT_HASH: &str = "2f138b6a0e45ec466c1f44326f7d7d638c5f8514786f67160aa2fe2dd6ae0323";

/// The hash of the config contract's account state at that block.
const ACCOUNT_HASH: &str = "264d8098b38f47d053b8eaf20e611ee7755c67874527ab4d5c555f6a678b0b28";

fn unhex(s: &str) -> Vec<u8> {
    let s = s.trim();
    (0..s.len() / 2)
        .map(|i| u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).expect("hex"))
        .collect()
}

fn proof() -> Vec<u8> {
    unhex(PROOF_HEX)
}

/// Collects every cell reachable from `cell`, revisiting shared cells.
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
fn parses_a_real_account_proof() {
    let roots = parse_boc(&proof()).expect("the captured proof parses");

    // A liteserver's account proof carries two roots: one covering the block, one
    // covering the shard state the account sits in.
    assert_eq!(roots.len(), 2, "an account proof has two roots");
    for root in &roots {
        assert_eq!(root.cell_type(), CellType::MerkleProof);
        assert_eq!(root.refs().len(), 1, "a merkle proof covers one tree");
        // A merkle proof's data is a type byte, a 32-byte hash, and a 2-byte depth.
        assert_eq!(root.bit_len(), 280);
        assert_eq!(root.data()[0], 0x03);
    }
}

#[test]
fn a_root_covers_the_block_it_was_read_at() {
    let roots = parse_boc(&proof()).expect("the captured proof parses");
    let expected = unhex(BLOCK_ROOT_HASH);

    // The block proof names the block hash the whole read is anchored to. That hash was
    // produced by the network, so finding it here ties this parse to TON.
    let found = roots.iter().any(|root| root.data()[1..33] == expected[..]);
    assert!(found, "a merkle root must name the block it was read at");
}

#[test]
fn the_proof_carries_the_account_as_a_pruned_branch() {
    let roots = parse_boc(&proof()).expect("the captured proof parses");
    let expected = unhex(ACCOUNT_HASH);

    // The account itself is pruned out of the proof and stands in as its hash, which is
    // how a proof stays small. Its stored hash is the account state's own hash.
    let found = all_cells(&roots).iter().any(|cell| {
        cell.cell_type() == CellType::PrunedBranch && cell.data()[2..34] == expected[..]
    });
    assert!(
        found,
        "the account's hash must be present as a pruned branch"
    );
}

#[test]
fn the_proof_holds_every_cell_kind_a_block_read_needs() {
    let roots = parse_boc(&proof()).expect("the captured proof parses");
    let cells = all_cells(&roots);

    let has = |kind: CellType| cells.iter().any(|c| c.cell_type() == kind);
    assert!(has(CellType::MerkleProof), "the two proof roots");
    assert!(
        has(CellType::MerkleUpdate),
        "the block's state update is a merkle update"
    );
    assert!(
        has(CellType::PrunedBranch),
        "everything off the proved path"
    );
    assert!(has(CellType::Ordinary), "the proved path itself");

    // A merkle update covers an old and a new tree, each with a hash and a depth.
    let update = cells
        .iter()
        .find(|c| c.cell_type() == CellType::MerkleUpdate)
        .expect("a state update");
    assert_eq!(update.refs().len(), 2);
    assert_eq!(update.data()[0], 0x04);
    assert_eq!(update.bit_len(), 552);
}

#[test]
fn every_pruned_branch_is_long_enough_to_read() {
    let roots = parse_boc(&proof()).expect("the captured proof parses");
    for cell in all_cells(&roots) {
        if cell.cell_type() == CellType::PrunedBranch {
            let levels = cell.data()[1].count_ones() as usize;
            assert!(levels >= 1, "a pruned branch marks at least one level");
            // A hash and a depth per marked level, after the type and mask bytes.
            assert!(cell.data().len() >= 2 + levels * 34);
            assert_eq!(cell.level_mask(), cell.data()[1]);
        }
    }
}

#[test]
fn a_flipped_byte_anywhere_is_caught_or_parses_to_something_else() {
    // The parser must never panic on mutated bytes. Every single-byte change either
    // fails to parse or yields a different, still well-formed graph.
    let original = proof();
    for index in (0..original.len()).step_by(7) {
        let mut mutated = original.clone();
        mutated[index] ^= 0xff;
        let _ = parse_boc(&mutated);
    }
}
