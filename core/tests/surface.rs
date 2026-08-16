// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Nirapod Labs

//! Whether the facade can name the types its own methods answer with.
//!
//! `docs/api-design.md` fixes that a consumer depends on `ton-net` and imports from one
//! place. A method that answers with a type the facade does not re-export breaks that on
//! its own: the call compiles inside this workspace, where every crate is a path away,
//! and outside it the caller has nowhere to put the result. The library's own build is
//! blind to the gap for the same reason, because the library names the lower crates
//! directly.
//!
//! So each case below binds a result to an explicitly written `ton_net::` type. Drop a
//! name from the re-export list in `crates/ton-net/src/lib.rs` and this file stops
//! compiling, which `cargo test` reports as a failure.
//!
//! Every cell type here arrives through the one `use ton_net::{..}` below, and nothing
//! under it reaches for `ton_net::cell` by path. That is a discipline this file keeps
//! rather than something cargo enforces: a test target inherits its crate's own
//! dependencies, so `ton_net::cell::Cell` would resolve here as readily as it does inside
//! the library, and writing it would quietly reopen the hole the file exists to close.
//!
//! # The scope, exactly
//!
//! This covers the methods enumerated here and nothing wider. It is a hand-kept list, so
//! a method added later is uncovered until a case for it is added; what it holds is that
//! the ones written down answer with types the facade names. Nothing here asserts the
//! re-export list is complete against the cell engine, because the list is deliberately
//! narrower than that engine.
//!
//! Every value is built in this file. Nothing reaches the network and no fixture is read,
//! because the question is about types rather than about bytes.

use ton_net::{
    parse_boc, serialize_boc, Builder, Cell, CellError, CellType, Dict, DictEntry, DictIter,
    Identity, Lookup, MsgAddress, Slice, MAX_BITS, MAX_CELLS, MAX_DEPTH, MAX_REFS,
};

/// The address stored in the sample cell and read back out of it.
const SAMPLE_ADDRESS: MsgAddress = MsgAddress::Std {
    workchain: -1,
    account: [0x11; 32],
};

/// A dictionary over 32-bit keys holding one entry, whose value is a single byte.
fn one_entry_dict(key: u32, value: u8) -> Dict {
    let mut dict = Dict::new(32).expect("32 is a legal key width");
    let mut leaf = Builder::new();
    leaf.store_uint(u64::from(value), 8)
        .expect("a byte fits an empty builder");
    dict.set(&key.to_be_bytes(), &leaf)
        .expect("one entry fits a fresh dictionary");
    dict
}

/// A cell shaped to reach every method the cases below need: a byte, an address, a
/// dictionary and a reference.
fn sample() -> (Cell, Cell) {
    let mut child = Builder::new();
    child
        .store_uint(0x5a, 8)
        .expect("a byte fits an empty builder");
    let child = child.build().expect("a one-byte cell builds");

    let mut root = Builder::new();
    root.store_uint(0xab, 8)
        .expect("a byte fits an empty builder");
    root.store_address(&SAMPLE_ADDRESS)
        .expect("an address fits beside a byte");
    root.store_dict(&one_entry_dict(7, 0x2c))
        .expect("a dictionary reference fits");
    root.store_ref(child.clone())
        .expect("a second reference fits");
    let root = root.build().expect("the root cell builds");

    (root, child)
}

#[test]
fn a_cell_answers_with_types_the_facade_names() {
    let (root, child) = sample();

    let kind: CellType = root.cell_type();
    assert_eq!(kind, CellType::Ordinary);

    // The identity holds a cell's hashes and depths, and `hash` is a shorthand over it,
    // so the two have to agree or one of the two names is pointing at the wrong thing.
    let identity: &Identity = root.identity();
    assert_eq!(identity.repr_hash(), root.hash());

    let builder: Builder = root.to_builder().expect("a cell converts to a builder");
    assert_eq!(builder.bits_used(), root.bit_len());

    assert_eq!(root.refs().len(), 2);
    assert_eq!(root.reference(1), Some(&child));
}

#[test]
fn a_slice_answers_with_types_the_facade_names() {
    let (root, _) = sample();

    let mut slice: Slice<'_> = root.parse();
    assert_eq!(slice.load_uint(8).expect("the leading byte reads"), 0xab);

    let address: MsgAddress = slice.load_address().expect("the address reads back");
    assert_eq!(address, SAMPLE_ADDRESS);

    let dict: Dict = slice.load_dict(32).expect("the dictionary reads back");

    let found: Lookup<DictEntry> = dict.get(&7u32.to_be_bytes()).expect("the lookup runs");
    let entry: DictEntry = found.found().expect("the key stored is present");
    let mut value: Slice<'_> = entry.slice().expect("the entry opens");
    assert_eq!(value.load_uint(8).expect("the value byte reads"), 0x2c);

    let mut walk: DictIter = dict.iter();
    let (key, _): (Vec<u8>, DictEntry) = walk
        .next()
        .expect("one entry is present")
        .expect("the walk does not fail");
    assert_eq!(key, 7u32.to_be_bytes());
    assert!(walk.next().is_none(), "the dictionary holds one entry");

    let rest: Builder = slice.to_builder().expect("what is left converts");
    assert_eq!(rest.refs_used(), 1, "the reference the dictionary left");
}

#[test]
fn a_bag_crosses_the_facade_in_both_directions() {
    let (root, _) = sample();

    // `Client::account_state` hands a proof and a state back as raw bag bytes, so a
    // facade that can write a bag and not read one leaves that escape hatch closed at the
    // far end. Both directions are named here, and the two forms of the write have to
    // agree with each other.
    let bag: Vec<u8> = root.to_boc().expect("a small tree serializes");
    let plural: Vec<u8> = serialize_boc(std::slice::from_ref(&root)).expect("one root serializes");
    assert_eq!(plural, bag);

    let read_back: Vec<Cell> = parse_boc(&bag).expect("what to_boc wrote parses back");
    assert_eq!(read_back.len(), 1);
    assert_eq!(read_back[0], root);
}

#[test]
fn a_failed_read_answers_with_the_cell_error_the_facade_names() {
    let empty = Builder::new().build().expect("an empty cell builds");

    // Bound to the named type rather than matched loosely, because what is at stake is
    // that a caller outside this workspace can hold what a failed read hands back.
    let failure: CellError = empty
        .parse()
        .load_uint(8)
        .expect_err("an empty cell has no byte to read");
    assert!(matches!(
        failure,
        CellError::NotEnoughBits {
            requested: 8,
            available: 0,
        }
    ));
}

#[test]
fn the_bounds_the_facade_names_are_the_ones_it_holds_to() {
    // A cell's two ceilings, checked against the builder that enforces them, so a
    // re-export pointing at some other constant fails here rather than misleading a
    // caller sizing what it stores.
    let mut full = Builder::new();
    full.store_same_bit(true, MAX_BITS)
        .expect("a cell holds MAX_BITS bits");
    assert_eq!(full.bits_left(), 0);
    assert!(
        full.store_bit(true).is_err(),
        "one bit past the ceiling is refused"
    );
    assert_eq!(Builder::new().refs_left(), MAX_REFS);

    // A bag's depth ceiling, checked the same way, through the two bag functions the
    // facade now carries.
    let mut chain = Builder::new().build().expect("a leaf forms");
    for _ in 0..=MAX_DEPTH {
        let mut link = Builder::new();
        link.store_ref(chain).expect("a reference fits");
        chain = link.build().expect("a link forms");
    }
    let too_deep = serialize_boc(std::slice::from_ref(&chain)).expect("a chain serializes");
    assert!(
        matches!(
            parse_boc(&too_deep),
            Err(CellError::TooDeep { limit: MAX_DEPTH })
        ),
        "a bag one link past the ceiling is refused, and the ceiling is the one named here"
    );

    // The cell ceiling is pinned at its figure rather than exercised: a bag holding one
    // cell more than this costs megabytes to build for an answer about naming. This
    // compares the re-exported constant against a literal, so what it catches is the
    // figure moving without this file moving with it, not the parser's use of it.
    let cells: usize = MAX_CELLS;
    assert_eq!(cells, 1 << 17);
}
