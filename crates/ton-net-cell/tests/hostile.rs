// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Nirapod Labs

//! Arbitrary and corrupted bytes, which every input to this crate might be.
//!
//! A bag of cells arrives from a liteserver nobody vouches for, so the parser's whole job
//! is to turn hostile bytes into either a cell tree or an error. A panic is neither: it
//! takes down a caller that was holding the parser at arm's length on purpose.
//!
//! Parsing is not where this ends. A tree that parses is then hashed, sliced, and
//! reserialized, and those run over lengths and indices the same bytes chose. So anything
//! that parses here is put through all of it.
//!
//! Random bytes rarely survive the magic number, so most of the work is done by mutating
//! a real bag of cells: single flipped bytes, truncations, and splices reach the deep
//! paths that arbitrary input never does.

use ton_net_cell::{parse_boc, Cell};

/// A real proof, the starting point every mutation works from.
const PROOF_HEX: &str = include_str!("fixtures/account-proof.hex");

/// A fixed-seed xorshift, so a failure reproduces exactly.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }

    fn below(&mut self, bound: usize) -> usize {
        if bound == 0 {
            0
        } else {
            #[allow(
                clippy::cast_possible_truncation,
                reason = "the result is < bound as u64, and bound: usize was widened losslessly into that u64, so it always fits back into usize"
            )]
            let result = (self.next() % bound as u64) as usize;
            result
        }
    }
}

fn unhex(s: &str) -> Vec<u8> {
    let s = s.trim();
    (0..s.len() / 2)
        .map(|i| u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).expect("hex"))
        .collect()
}

/// Reads a parsed cell the way a caller would, so a panic in any of it fails the test.
///
/// The slice reads run off the end of every cell on purpose, since a caller decoding an
/// unknown structure does that all the time and must get an error rather than a crash.
fn exercise(cell: &Cell) {
    let _ = cell.hash();
    let _ = cell.repr_hash();
    let _ = cell.depth();
    for level in 0..4 {
        let _ = cell.hash_at(level);
        let _ = cell.depth_at(level);
    }

    let mut slice = cell.parse();
    // More reads than any cell can satisfy, so the tail of this loop is always the
    // past-the-end case.
    for _ in 0..8 {
        let _ = slice.load_bit();
        let _ = slice.load_uint(64);
        let _ = slice.load_uint128(128);
        let _ = slice.load_var_uint(7);
        let _ = slice.load_bytes(32);
        let _ = slice.load_maybe_ref();
    }

    for child in cell.refs() {
        exercise(child);
    }
}

fn exercise_roots(roots: &[Cell]) {
    for root in roots {
        // Serializing walks the whole graph from the root, so it belongs here rather than
        // once per cell, where it would repeat that walk for every subtree.
        let _ = root.to_boc();
        exercise(root);
    }
}

#[test]
fn arbitrary_bytes_never_panic() {
    let mut rng = Rng(0x9E37_79B9_7F4A_7C15);
    for _ in 0..20_000 {
        let n = rng.below(128);
        let bytes: Vec<u8> = (0..n).map(|_| (rng.next() & 0xff) as u8).collect();
        if let Ok(roots) = parse_boc(&bytes) {
            exercise_roots(&roots);
        }
    }
}

#[test]
fn bytes_that_start_like_a_bag_of_cells_never_panic() {
    // The magic number gates almost everything, so arbitrary input stops at the door.
    // Prefixing it puts the random bytes where the header, the counts, and the cell
    // descriptors are read.
    let mut rng = Rng(0x243F_6A88_85A3_08D3);
    for _ in 0..20_000 {
        let mut bytes = vec![0xb5, 0xee, 0x9c, 0x72];
        let n = rng.below(96);
        bytes.extend((0..n).map(|_| (rng.next() & 0xff) as u8));
        if let Ok(roots) = parse_boc(&bytes) {
            exercise_roots(&roots);
        }
    }
}

#[test]
fn a_corrupted_real_bag_never_panics() {
    // A real bag reaches every part of the parser, so mutating one covers the deep paths
    // that random bytes cannot reach: reference indices, cell descriptors, and the
    // offsets that say how far the data of each cell runs.
    let proof = unhex(PROOF_HEX);
    parse_boc(&proof).expect("the fixture parses before it is corrupted");

    let mut rng = Rng(0xB7E1_5162_8AED_2A6B);
    for _ in 0..20_000 {
        let mut bytes = proof.clone();
        for _ in 0..=rng.below(4) {
            let at = rng.below(bytes.len());
            bytes[at] ^= 1 << rng.below(8);
        }
        if let Ok(roots) = parse_boc(&bytes) {
            exercise_roots(&roots);
        }
    }
}

#[test]
fn a_truncated_or_spliced_real_bag_never_panics() {
    // Every prefix of a real bag, and pieces of one lifted out of the middle. A length
    // read from the bytes that outruns what is left is the classic way a parser panics.
    let proof = unhex(PROOF_HEX);

    for end in 0..proof.len() {
        if let Ok(roots) = parse_boc(&proof[..end]) {
            exercise_roots(&roots);
        }
    }

    let mut rng = Rng(0xBB67_AE85_84CA_A73B);
    for _ in 0..10_000 {
        let start = rng.below(proof.len());
        let end = start + rng.below(proof.len() - start);
        if let Ok(roots) = parse_boc(&proof[start..end]) {
            exercise_roots(&roots);
        }
    }
}

#[test]
fn what_survives_reserialization_parses_back() {
    // Reserializing a corrupted tree that parsed must produce bytes that parse again, and
    // to the same identities. A cell whose bag cannot be read back would be one this
    // crate accepts but cannot write.
    let proof = unhex(PROOF_HEX);
    let mut rng = Rng(0x3C6E_F372_FE94_F82B);
    let mut checked = 0;

    for _ in 0..5_000 {
        let mut bytes = proof.clone();
        let at = rng.below(bytes.len());
        bytes[at] ^= 1 << rng.below(8);

        let Ok(roots) = parse_boc(&bytes) else {
            continue;
        };
        for root in &roots {
            let Ok(written) = root.to_boc() else {
                continue;
            };
            let read = parse_boc(&written).expect("a bag this crate wrote parses back");
            assert_eq!(read.len(), 1, "a single-root bag reads back as one root");
            assert_eq!(
                read[0].repr_hash(),
                root.repr_hash(),
                "a round trip changed a cell's identity"
            );
            checked += 1;
        }
    }

    // Without this the test could pass having reserialized nothing at all.
    assert!(checked > 0, "no corrupted tree survived to be reserialized");
}
