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
//!
//! Building runs alongside it: a proof built here over the tree a server's proof stands for
//! reproduces that server's proof cell byte for byte, which pins the layout to real bytes.

use ton_net::cell::{
    apply_update, create_proof, create_update, parse_boc, validate_update, virtualize, Cell,
    CellType, UsageTree,
};

/// The account proof captured from mainnet, a bag of Merkle proofs.
const ACCOUNT_PROOF: &str = include_str!("../fixtures/account-proof.hex");

/// The masterchain block hash the bag was captured under. One proof stands for it.
const PROOF_BLOCK_HASH: &str = "2f138b6a0e45ec466c1f44326f7d7d638c5f8514786f67160aa2fe2dd6ae0323";

/// A whole basechain block, and the root hash the liteserver served it under.
const BASECHAIN_BLOCK: &str = include_str!("../fixtures/block-basechain.hex");
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

/// Every cell reachable from `cell`, revisiting a shared subtree as many times as it is
/// referenced, since what is being counted is what the tree holds and not what it deduplicates
/// to.
fn walk(cell: &Cell, out: &mut Vec<Cell>) {
    out.push(cell.clone());
    for child in cell.refs() {
        walk(child, out);
    }
}

/// How many of the cells under `cell` are of `kind`.
fn count_of(cell: &Cell, kind: CellType) -> usize {
    let mut cells = Vec::new();
    walk(cell, &mut cells);
    cells.iter().filter(|c| c.cell_type() == kind).count()
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

#[test]
fn pruning_a_mainnet_block_to_two_disjoint_paths_keeps_both() {
    let roots = parse_boc(&unhex(BASECHAIN_BLOCK)).expect("the block parses");
    let block = &roots[0];

    // Two cells three hops down that share only the extra above them, so the marked set is a
    // fork rather than a chain: a proof of both has to keep two branches of one node, which a
    // single-path proof never exercises.
    let extra = block
        .reference(3)
        .expect("a block holds an extra reference");
    let left = extra
        .reference(0)
        .and_then(|child| child.reference(0))
        .expect("the first branch of the extra");
    let right = extra
        .reference(2)
        .and_then(|child| child.reference(0))
        .expect("the third branch of the extra");
    assert_ne!(left.hash(), right.hash(), "the two targets are two cells");

    let mut usage = UsageTree::new(block.clone());
    assert!(usage.mark_path(left), "the left target is in the block");
    assert!(usage.mark_path(right), "the right target is in the block");
    let skeleton = usage.prune().expect("the skeleton builds");

    // The root hash is the liteserver's own, so the multi-path skeleton is held to a value
    // from outside this engine rather than to its own arithmetic.
    assert_eq!(
        hex(skeleton.hash()),
        BASECHAIN_ROOT,
        "a two-path skeleton does not hash to the block it was pruned from"
    );

    let kept_extra = skeleton.reference(3).expect("the extra is kept");
    assert_eq!(kept_extra.cell_type(), CellType::Ordinary);
    let kept_left = kept_extra
        .reference(0)
        .and_then(|child| child.reference(0))
        .expect("the left path survives");
    let kept_right = kept_extra
        .reference(2)
        .and_then(|child| child.reference(0))
        .expect("the right path survives");
    assert_eq!(kept_left.cell_type(), CellType::Ordinary);
    assert_eq!(kept_right.cell_type(), CellType::Ordinary);
    assert_eq!(kept_left.hash(), left.hash(), "the left target reads back");
    assert_eq!(
        kept_right.hash(),
        right.hash(),
        "the right target reads back"
    );

    // The branch of the fork nobody marked is stood in for, which is what makes the two above
    // a fact about the marking rather than about the tree being kept whole.
    assert_eq!(
        kept_extra
            .reference(1)
            .expect("the unmarked branch is there")
            .cell_type(),
        CellType::PrunedBranch,
    );

    // And marking one path alone prunes the other, so keeping both is what the second mark
    // bought.
    let mut one = UsageTree::new(block.clone());
    assert!(one.mark_path(left), "the left target is in the block");
    let single = one.prune().expect("the single-path skeleton builds");
    assert_eq!(hex(single.hash()), BASECHAIN_ROOT);
    assert_eq!(
        single
            .reference(3)
            .and_then(|extra| extra.reference(2))
            .expect("the right branch is there")
            .cell_type(),
        CellType::PrunedBranch,
        "the unmarked path should have been stood in for"
    );
}

#[test]
fn applying_a_mainnet_state_update_to_a_pruned_base_keeps_the_pruning() {
    let roots = parse_boc(&unhex(BASECHAIN_BLOCK)).expect("the block parses");
    let block = &roots[0];
    let update = block.reference(2).expect("a block holds a state update");
    assert_eq!(update.cell_type(), CellType::MerkleUpdate);

    // The base here is the update's own old side, which the network wrote as a skeleton: it
    // stands for the old state without holding it, and answers at level zero with the old
    // state's hash, so it is a base this update transforms.
    let old_side = update.reference(0).expect("the old side");
    assert_ne!(
        count_of(old_side, CellType::PrunedBranch),
        0,
        "the fixture's old side is a skeleton, not a whole state"
    );

    let rebuilt = apply_update(old_side, update).expect("a pruned base is not refused");

    // The new state hash is the network's own value, sitting in the update's data past the
    // tag and the old hash.
    assert_eq!(
        &rebuilt.hash()[..],
        &update.data()[33..65],
        "the rebuilt tree is not the state the update names"
    );

    // What came back stands for the new state at the same reach the base had. Grafting from a
    // skeleton carries the skeleton's pruned branches into the answer, and the tree says so:
    // it holds pruned branches and stands above level zero.
    assert_ne!(count_of(&rebuilt, CellType::PrunedBranch), 0);
    assert_ne!(rebuilt.level_mask(), 0);

    // The state also holds a library reference, a cell that names code by hash and stands in
    // for nothing. It is content the new side revealed, so it is carried through rather than
    // looked for in the base.
    assert_eq!(
        count_of(&rebuilt, CellType::LibraryReference),
        count_of(
            update.reference(1).expect("the new side"),
            CellType::LibraryReference
        ),
        "every library reference the new side revealed is in the rebuilt state"
    );
    assert_ne!(
        count_of(&rebuilt, CellType::LibraryReference),
        0,
        "the fixture's new side reveals a library reference"
    );
}

#[test]
fn a_proof_built_here_reproduces_the_server_proof() {
    let roots = parse_boc(&unhex(ACCOUNT_PROOF)).expect("the proof parses");
    let mut proofs = 0usize;
    for root in &roots {
        if root.cell_type() != CellType::MerkleProof {
            continue;
        }
        proofs += 1;
        // The tree the server's proof stands for, wrapped again here, has to reproduce the
        // server's proof cell exactly. A different tag position, field width or byte order
        // would part from real bytes right here.
        let content = virtualize(root).expect("the server proof virtualizes");
        let rebuilt = create_proof(&content).expect("the covered tree is provable");
        assert_eq!(rebuilt.repr_hash(), root.repr_hash());
    }
    assert!(proofs >= 1, "the bag holds no merkle proofs to rebuild");
}

#[test]
fn an_update_built_here_reproduces_a_mainnet_block_update() {
    let roots = parse_boc(&unhex(BASECHAIN_BLOCK)).expect("the block parses");
    let block = &roots[0];
    // A block stores its state transition as a Merkle update, its third reference.
    let update = block.reference(2).expect("a block holds a state update");
    assert_eq!(update.cell_type(), CellType::MerkleUpdate);

    // Rebuilt from the two sides the real update reveals, the update reproduces the real
    // cell byte for byte, which pins the update layout to real liteserver bytes.
    let old = update.reference(0).expect("the old side");
    let new = update.reference(1).expect("the new side");
    let rebuilt = create_update(old, new).expect("the update rebuilds");
    assert_eq!(rebuilt.repr_hash(), update.repr_hash());

    // It validates against itself, and names the new state the block leaves behind, which is
    // the root an account proof for this block must reproduce.
    validate_update(&rebuilt).expect("a mainnet update validates");
    assert_eq!(&new.hash()[..], &update.data()[33..65]);
}
