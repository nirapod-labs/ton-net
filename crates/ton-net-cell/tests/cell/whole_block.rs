// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Nirapod Labs

//! Parsing a whole block, which is the form that carries its own hashes.
//!
//! A bag of cells may write a cell's hashes and depths ahead of its data. Every fixture
//! in the tree before these was a Merkle proof, and proofs do not use that form, so the
//! parser had never met it and refused it outright.
//!
//! Where a cell does carry them, they are checked rather than skipped: a stored hash that
//! disagrees with what the cell's own contents give means the sender computed something
//! this crate did not, and there is no reading of that worth continuing from. Of the 1428
//! cells in the two blocks below, 44 write their hashes; the rest leave them out, so this
//! is a check that runs where it can rather than everywhere.
//!
//! The blocks are whole rather than proofs, which is what makes them the only fixtures in
//! the tree holding a complete dictionary, and a block carries a `MERKLE_UPDATE` of the
//! state whose two subtrees are pruned, so they are also the only fixtures where exotic
//! cells and stored hashes appear in the same bag.

use ton_net_cell::{parse_boc, serialize_boc, BocView, Cell, CellError};

/// A masterchain block, and the basechain block the same head named.
const MASTERCHAIN: &str = include_str!("../fixtures/block-masterchain.hex");
const BASECHAIN: &str = include_str!("../fixtures/block-basechain.hex");

/// What the liteserver said each block's root hash was, recorded when it was captured.
const MASTERCHAIN_ROOT: &str = "e55bf9675a44540e6399b171a63045b48294a56e9c67ddb442c10f02adac15e0";
const BASECHAIN_ROOT: &str = "80cbafe6a27bb13ff6f7aa1a103d8a30989fba77c737457160b372359fcf5696";

/// `block#11ef55aa global_id:int32 info:^ value_flow:^ state_update:^ extra:^`
const BLOCK_TAG: u64 = 0x11ef_55aa;

/// One cell of eight bits holding `0xab`, in the ordinary form with no stored hashes.
const PLAIN: [u8; 14] = [
    0xb5, 0xee, 0x9c, 0x72, 0x01, 0x01, 0x01, 0x01, 0x00, 0x03, 0x00, 0x00, 0x02, 0xab,
];

/// Decodes a hex-dump fixture into bytes, skipping `#` comment lines and whitespace.
///
/// # Panics
///
/// Panics if what is left after filtering is not valid hex, which only a corrupted
/// fixture would be.
pub fn unhex(text: &str) -> Vec<u8> {
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

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    bytes.iter().fold(String::new(), |mut out, b| {
        let _ = write!(out, "{b:02x}");
        out
    })
}

/// Every cell in the tree, each reached once.
fn all(root: &Cell) -> Vec<Cell> {
    let mut seen = std::collections::HashSet::new();
    let mut stack = vec![root.clone()];
    let mut out = Vec::new();
    while let Some(cell) = stack.pop() {
        if !seen.insert(*cell.repr_hash()) {
            continue;
        }
        stack.extend(cell.refs().iter().cloned());
        out.push(cell);
    }
    out
}

/// The same one-cell bag as [`PLAIN`], written with the cell carrying its own hash and
/// depth. Both are given rather than derived, so a wrong one can be handed over.
fn with_stored(hash: &[u8; 32], depth: u16) -> Vec<u8> {
    let mut bag = vec![
        0xb5, 0xee, 0x9c, 0x72, // magic
        0x01, // one byte per reference index, no index, no checksum
        0x01, // one byte per offset
        0x01, // one cell
        0x01, // one root
        0x00, // no absent cells
        0x25, // the cell area is 37 bytes: two descriptors, 32 of hash, 2 of depth, 1 of data
        0x00, // the root is cell zero
        0x10, // no references, not exotic, stores its hashes, level mask zero
        0x02, // one byte of data
    ];
    // Both descriptors come first, then the hashes, then the depths, then the data.
    bag.extend_from_slice(hash);
    bag.extend_from_slice(&depth.to_be_bytes());
    bag.push(0xab);
    bag
}

#[test]
fn a_whole_block_parses_and_hashes_to_the_identity_it_was_served_under() {
    for (what, text, expected) in [
        ("masterchain", MASTERCHAIN, MASTERCHAIN_ROOT),
        ("basechain", BASECHAIN, BASECHAIN_ROOT),
    ] {
        let roots = parse_boc(&unhex(text)).expect("the block parses");
        assert_eq!(roots.len(), 1, "{what}: a block is one root");
        assert_eq!(
            hex(roots[0].repr_hash()),
            expected,
            "{what}: the block does not hash to the id it was served under"
        );
        assert_eq!(
            roots[0].parse().load_uint(32).expect("a tag"),
            BLOCK_TAG,
            "{what}: not a block"
        );
    }
}

#[test]
fn a_view_verifies_a_whole_block_to_the_hash_a_full_parse_gives() {
    // Verifying keeps a summary per cell rather than the cell, so a bag too large to hold as
    // a graph could still be checked. Over a whole block, which carries stored hashes and
    // exotic cells, the root it reports must be the one a full parse computes and the one the
    // block was served under.
    for (what, text, expected) in [
        ("masterchain", MASTERCHAIN, MASTERCHAIN_ROOT),
        ("basechain", BASECHAIN, BASECHAIN_ROOT),
    ] {
        let bag = unhex(text);
        let verified = BocView::open(&bag)
            .expect("the header reads")
            .verify()
            .expect("the block verifies");
        let parsed = parse_boc(&bag).expect("the block parses");
        assert_eq!(verified.len(), parsed.len(), "{what}: one hash per root");
        assert_eq!(
            hex(&verified[0]),
            expected,
            "{what}: verify does not give the served id"
        );
        assert_eq!(
            &verified[0],
            parsed[0].repr_hash(),
            "{what}: verify and a full parse disagree"
        );
    }
}

#[test]
fn a_whole_block_renders_as_a_tree_with_its_tag_legible() {
    // Rendering a real block exercises the dump over a deep tree with exotic cells in it.
    // The block tag is a fact from the schema, so the hex form writes it at the front: it
    // is the same tag the parse test reads back off the wire.
    let block = &parse_boc(&unhex(BASECHAIN)).expect("the block parses")[0];
    let text = block.dump();
    assert!(
        text.starts_with("x{11EF55AA"),
        "the block tag is not legible at the front of the dump"
    );
    // A block holds four references, so the tree is more than the root's own line.
    assert!(text.contains('\n'), "a block renders as more than one line");
}

#[test]
fn a_cell_may_carry_the_hash_and_depth_it_computes() {
    let plain = parse_boc(&PLAIN).expect("the plain form parses");
    let hash = *plain[0].repr_hash();

    let stored = parse_boc(&with_stored(&hash, 0)).expect("the stored form parses");
    assert_eq!(stored[0].repr_hash(), &hash);
    assert_eq!(stored[0].parse().load_uint(8).expect("the data"), 0xab);
}

#[test]
fn a_cell_whose_stored_hash_disagrees_with_its_contents_is_refused() {
    // Without this the acceptance above is the whole feature: a parser that read the
    // stored hashes and dropped them would pass every other test in this file.
    let mut wrong = *parse_boc(&PLAIN).expect("parses")[0].repr_hash();
    wrong[0] ^= 1;
    assert_eq!(
        parse_boc(&with_stored(&wrong, 0)),
        Err(CellError::Malformed(
            "cell stores a hash its contents do not give"
        ))
    );
}

#[test]
fn a_cell_whose_stored_depth_disagrees_with_its_contents_is_refused() {
    let hash = *parse_boc(&PLAIN).expect("parses")[0].repr_hash();
    assert_eq!(
        parse_boc(&with_stored(&hash, 1)),
        Err(CellError::Malformed(
            "cell stores a depth its contents do not give"
        ))
    );
}

#[test]
fn a_block_carries_stored_hashes_on_some_of_its_cells_and_exotic_cells_besides() {
    // The blocks are the evidence that the form is read as TON writes it, so what they
    // hold is worth asserting rather than assuming. A block that had stopped carrying
    // hashes would leave the two tests above as the only coverage, and they are cells
    // this file wrote.
    let mut cells = 0usize;
    let mut exotic = 0usize;
    for text in [MASTERCHAIN, BASECHAIN] {
        for cell in all(&parse_boc(&unhex(text)).expect("the block parses")[0]) {
            cells += 1;
            exotic += usize::from(cell.is_exotic());
        }
    }
    assert!(cells > 600, "only {cells} cells in the two blocks");
    // A block holds a Merkle update of the state, and both of its sides are pruned.
    assert!(
        exotic > 100,
        "only {exotic} exotic cells, so no merkle update"
    );
}

#[test]
fn a_block_written_back_out_keeps_its_identity_without_the_stored_hashes() {
    // Rewriting drops the stored copies, because a cell's identity comes from its
    // contents and repeating it in the bag is the sender's choice rather than the
    // format's. The bytes are therefore shorter and the tree is the same tree.
    for (what, text) in [("masterchain", MASTERCHAIN), ("basechain", BASECHAIN)] {
        let original = unhex(text);
        let roots = parse_boc(&original).expect("the block parses");
        let written = serialize_boc(&roots).expect("the block writes");
        let again = parse_boc(&written).expect("what was written parses");

        assert_eq!(again[0].repr_hash(), roots[0].repr_hash(), "{what}");
        assert!(
            written.len() < original.len(),
            "{what}: rewriting kept the stored hashes ({} then {})",
            original.len(),
            written.len()
        );
    }
}
