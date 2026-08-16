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

use ton_net::cell::{
    parse_boc, serialize_boc, BocView, Builder, Cell, CellError, LazyBoc, MAX_DEPTH,
};

/// A real proof, the starting point every mutation works from.
const PROOF_HEX: &str = include_str!("../fixtures/account-proof.hex");

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

/// A two-cell bag, each cell flawed or sound as asked, the two flaws independent.
///
/// Neither cell references the other, so neither failure hides the other. A flawed cell
/// beneath another leaves its parent unbuildable, and then there is one failure to report
/// and no choice between failures to make.
///
/// Cell zero claims a level mask its children would have to justify, and it carries no
/// children. Cell one carries the hash and depth a cell may store ahead of its data,
/// filled with bytes its own contents do not produce. Both faults are found where a bag's
/// cells are finalized rather than where its bytes are read, which is the pass whose order
/// the test below pins.
fn two_flawed_cells(first_flawed: bool, second_flawed: bool) -> Vec<u8> {
    // d1 is 32 * level_mask + 8 * exotic + reference count, and bit four says the cell
    // carries its own hashes and depths ahead of its data. d2 is zero for a cell with no
    // data bits.
    let mut cells = vec![
        if first_flawed { 0x20 } else { 0x00 },
        0x00,
        if second_flawed { 0x10 } else { 0x00 },
        0x00,
    ];
    if second_flawed {
        // One hash and one depth, which is what a cell of an empty level mask stores, and
        // no part of it is what this cell's contents hash to.
        cells.extend([0xaa; 34]);
    }

    let mut bag = vec![
        0xb5, 0xee, 0x9c, 0x72, // magic
        0x01, // one byte per reference, no index, no checksum
        0x01, // one byte per offset
        0x02, // two cells
        0x01, // one root
        0x00, // no absent cells
    ];
    bag.push(u8::try_from(cells.len()).expect("the cell area is under 256 bytes"));
    bag.push(0x00); // the root is cell zero
    bag.extend(cells);
    bag
}

#[test]
fn a_bag_with_two_flawed_cells_is_refused_for_the_lower_one() {
    // Which failure a bag with more than one comes back with must not depend on the order
    // its cells were finalized in, or the same bytes would produce different errors as
    // that order changed. The rule is that the lowest cell index wins. The two cells here
    // fail for different reasons, so which one the rule picked is legible in the error.
    const BY_LEVEL: CellError =
        CellError::Malformed("cell level mask is not the one its children imply");
    const BY_HASH: CellError = CellError::Malformed("cell stores a hash its contents do not give");

    // Each flaw on its own, which is what says the pair below was refused for the fault
    // planted in one cell rather than for anything the two cells share.
    assert_eq!(
        parse_boc(&two_flawed_cells(true, false)),
        Err(BY_LEVEL),
        "the first cell claims a level nothing below it gives it"
    );
    assert_eq!(
        parse_boc(&two_flawed_cells(false, true)),
        Err(BY_HASH),
        "the second cell stores a hash its contents do not give"
    );

    // Both at once. Finalizing runs from the highest cell index down, so the second cell's
    // failure is the one met first and the first cell's is the one reported.
    assert_eq!(
        parse_boc(&two_flawed_cells(true, true)),
        Err(BY_LEVEL),
        "a bag failing at two cells reports the lower of them"
    );

    // And the same bag with neither flaw is read, so the shape itself is not what was
    // being refused.
    let sound = parse_boc(&two_flawed_cells(false, false))
        .expect("two sound cells make a bag this crate reads");
    exercise_roots(&sound);
}

/// A two-cell bag whose root references a cell that will not build.
///
/// The child claims a level mask nothing beneath it gives it, which is a fault found where
/// the bag's cells are finalized. The root above it is then a cell no pass can build, and
/// the failure it has is a missing child rather than a fault of its own.
fn a_flaw_under_a_parent() -> Vec<u8> {
    let cells = vec![
        0x01, // the root, one reference and no data bits
        0x00, 0x01, // which points at cell one
        0x20, // the child, claiming a level its children would have to justify
        0x00,
    ];

    let mut bag = vec![
        0xb5, 0xee, 0x9c, 0x72, // magic
        0x01, // one byte per reference, no index, no checksum
        0x01, // one byte per offset
        0x02, // two cells
        0x01, // one root
        0x00, // no absent cells
    ];
    bag.push(u8::try_from(cells.len()).expect("the cell area is under 256 bytes"));
    bag.push(0x00); // the root is cell zero
    bag.extend(cells);
    bag
}

#[test]
fn a_cell_built_on_its_own_is_refused_for_the_cell_that_failed() {
    // Reading one cell of a bag walks its subtree and builds it from the bottom, which is
    // a third pass over the same cells beside the whole-bag build and the identity-only
    // verify. A caller that asks for a cell and a caller that parses the bag are looking
    // at the same bytes, so a fault beneath the cell asked for has to come back as the
    // fault it is rather than as the parent's missing child.
    const BY_LEVEL: CellError =
        CellError::Malformed("cell level mask is not the one its children imply");

    let bag = a_flaw_under_a_parent();
    assert_eq!(
        parse_boc(&bag),
        Err(BY_LEVEL),
        "the child claims a level nothing below it gives it"
    );

    // The cell above the fault, which is the case that has a choice to make: it can report
    // what stopped it, a child that produced no cell, or what stopped the child.
    let lazy = LazyBoc::open(&bag).expect("every cell reads, and none of them is built");
    assert_eq!(
        lazy.cell(0).err(),
        Some(BY_LEVEL),
        "reading one cell named its parent's missing child in place of the fault under it"
    );
    assert_eq!(
        BocView::open(&bag).expect("the header reads").cell(0).err(),
        Some(BY_LEVEL),
        "and the same through a view, which reads the bag again for the one cell"
    );

    // The flawed cell asked for directly, where there is nothing above it to report
    // instead. Both callers agree with the whole-bag read on this one too.
    assert_eq!(lazy.cell(1).err(), Some(BY_LEVEL));
}

/// A serialized bag holding one chain: a leaf under `links` parents, so its root has depth
/// `links`. Both assertions below rest on that being the depth and not one either side of it.
pub fn deep_chain(links: usize) -> Vec<u8> {
    let mut cell = Builder::new().build().expect("a leaf forms");
    for _ in 0..links {
        let mut builder = Builder::new();
        builder.store_ref(cell).expect("a reference fits");
        cell = builder.build().expect("a cell forms");
    }
    serialize_boc(std::slice::from_ref(&cell)).expect("a chain serializes")
}

#[test]
fn a_bag_deeper_than_the_limit_is_refused() {
    // The depth limit is the only thing between a bag a peer chose and a chain long enough to
    // take the stack with it. Reading it is not where that happens: parsing costs the same at
    // any depth, and `stack.rs` holds it to that. Releasing it is, because a cell holds its
    // children and letting go of the last handle on a chain lets go of the next, and so is
    // every walk that takes a frame per reference, which `stack.rs` measures at the limit.
    // Both sides are asserted here: refusing the deep bag is what a limit that refuses
    // everything also does, so the shallow one has to be read.
    let at_limit = deep_chain(MAX_DEPTH);
    assert!(
        parse_boc(&at_limit).is_ok(),
        "a bag at the limit is a legal bag"
    );

    let past_limit = deep_chain(MAX_DEPTH + 1);
    assert!(
        matches!(
            parse_boc(&past_limit),
            Err(CellError::TooDeep { limit: MAX_DEPTH })
        ),
        "a bag one link past the limit is refused"
    );
}
