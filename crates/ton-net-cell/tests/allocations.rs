// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Nirapod Labs

//! What reading a bag of cells costs the allocator.
//!
//! Wall-clock timing on the machine this was written on swings by tens of percent between
//! runs of identical code, which is enough to hide a real regression and enough to invent
//! one. A count does not move with the weather: reading the same bag calls the allocator the
//! same number of times every run, on every machine, and that count is what the memory a
//! large bag needs is proportional to. So the layout is held to a count rather than a clock.
//!
//! What the counts say today, on the captured mainnet fixtures:
//!
//! | bag | cells | building | verifying |
//! |---|---:|---:|---:|
//! | account proof | 45 | 92 | 47 |
//! | basechain block | 1121 | 2013 | 892 |
//!
//! One of those per cell is the cell itself. The other is the hashes above the lowest, which
//! only a cell significant at more than one level has, and 886 of the block's 1121 cells are.
//! A pruned branch carries a mask of its own, and the mask reaches its ancestors until a Merkle
//! cell shifts it away, which is why 886 and not all 1121. Nothing else in a read is per cell.
//!
//! Counting them at all means installing a global allocator, and a global allocator means
//! `unsafe`. That is why this is a test binary and not the library: the library forbids
//! unsafe code and goes on forbidding it, and a test binary is a crate of its own.

use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;

use ton_net_cell::{parse_boc, serialize_boc, BocView, Builder};

thread_local! {
    /// Calls to the allocator on this thread since the count was last cleared.
    ///
    /// Per thread rather than global because the test harness runs tests side by side, and a
    /// count shared between them would report whatever the others happened to be doing.
    static CALLS: Cell<usize> = const { Cell::new(0) };
}

/// The system allocator, counting every call that asks it for memory.
struct Counting;

/// Records one call, if this thread still has somewhere to record it.
///
/// A thread tears its locals down before it ends, and the allocator stays in use after that.
/// Nothing being measured runs then, so a call that arrives with nowhere to go is dropped.
fn count() {
    let _ = CALLS.try_with(|counter| counter.set(counter.get() + 1));
}

unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        count();
        System.alloc(layout)
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        System.dealloc(ptr, layout);
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        // A vector that outgrows itself asks for memory again, which is a cost worth counting
        // whether or not the old block could be extended in place.
        count();
        System.realloc(ptr, layout, new_size)
    }
}

#[global_allocator]
static ALLOCATOR: Counting = Counting;

/// Runs `body` and reports how many times it asked the allocator for memory.
fn calls_to_allocate<T>(body: impl FnOnce() -> T) -> (T, usize) {
    CALLS.with(|counter| counter.set(0));
    let value = body();
    let counted = CALLS.with(Cell::get);
    (value, counted)
}

/// Headroom over what a read costs beyond its cells, which is a buffer for the bag and a few
/// vectors sized once.
///
/// Measured at six. The bounds below are stated with room over that rather than against it, so
/// that a vector growing one step differently is not a failing test, while anything per cell
/// still is.
const SLACK: usize = 16;

/// The captured mainnet account proof, hex encoded.
const PROOF_HEX: &str = include_str!("fixtures/account-proof.hex");

/// A captured mainnet basechain block, the large bag of the two.
const BLOCK_HEX: &str = include_str!("fixtures/block-basechain.hex");

/// Decodes a hex-dump fixture, skipping comment lines and whitespace.
fn unhex(text: &str) -> Vec<u8> {
    let hex: String = text
        .lines()
        .filter(|line| !line.starts_with('#'))
        .flat_map(str::chars)
        .filter(|c| !c.is_whitespace())
        .collect();
    (0..hex.len() / 2)
        .map(|i| u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).expect("the fixture is hex"))
        .collect()
}

/// How many cells a bag holds, read from its header without building anything.
fn cells_in(bag: &[u8]) -> usize {
    BocView::open(bag).expect("the fixture opens").cell_count()
}

#[test]
fn building_a_bag_costs_one_allocation_for_a_cell_and_one_for_its_higher_hashes() {
    for (name, bag) in [
        ("account proof", unhex(PROOF_HEX)),
        ("basechain block", unhex(BLOCK_HEX)),
    ] {
        let cells = cells_in(&bag);
        let (roots, asked) = calls_to_allocate(|| parse_boc(&bag).expect("the fixture parses"));
        assert!(!roots.is_empty());

        // A cell costs its own allocation, and one more only for the hashes above the
        // lowest. Its data is a window on one buffer the whole bag shares, and its
        // references, level mask, hash and depth all sit inside it, so none of those is an
        // allocation at all.
        assert!(
            asked <= cells * 2 + SLACK,
            "reading the {name} built {cells} cells and asked the allocator {asked} times, \
             which is more than a cell and its higher hashes apiece"
        );
    }
}

#[test]
fn a_bag_of_ordinary_cells_costs_at_most_one_allocation_for_each() {
    // Every cell here has an empty level mask, so none of them has a hash above the lowest
    // and none of them may cost a second allocation. This is the shape a contract's code, a
    // message body and a shard state all have.
    const DEPTH: usize = 200;

    let mut cell = Builder::new().build().expect("an empty cell");
    for step in 0..DEPTH {
        let mut builder = Builder::new();
        builder.store_uint(step as u64, 64).expect("a word fits");
        builder.store_ref(cell).expect("a reference fits");
        cell = builder.build().expect("well formed");
    }
    let bag = serialize_boc(std::slice::from_ref(&cell)).expect("serializes");

    let cells = cells_in(&bag);
    assert_eq!(cells, DEPTH + 1, "one cell per step, and the leaf");
    for held in parse_boc(&bag).expect("parses") {
        assert_eq!(
            held.level_mask(),
            0,
            "nothing here is significant above zero"
        );
    }

    let (_, asked) = calls_to_allocate(|| parse_boc(&bag).expect("parses"));
    assert!(
        asked <= cells + SLACK,
        "reading {cells} ordinary cells asked the allocator {asked} times, which is more \
         than one apiece: something is allocating for a cell's contents again"
    );
}

#[test]
fn verifying_a_bag_costs_less_than_building_it() {
    let bag = unhex(BLOCK_HEX);
    let cells = cells_in(&bag);

    let (built, building) = calls_to_allocate(|| {
        BocView::open(&bag)
            .expect("opens")
            .materialize()
            .expect("builds")
    });
    let (verified, verifying) = calls_to_allocate(|| {
        BocView::open(&bag)
            .expect("opens")
            .verify()
            .expect("verifies")
    });

    assert_eq!(
        built.len(),
        verified.len(),
        "both read the same bag to the same roots"
    );
    // Verifying keeps an identity per cell rather than a cell, and an identity holds its own
    // hash and depth, so the cells it allocates for are only the ones significant above the
    // lowest level. Building allocates for every cell on top of that. Verifying is the path a
    // bag too large to hold as a graph goes down, so it has to be the cheaper one.
    //
    // Exactly one allocation per cell separates them, because that one is the cell itself and
    // verifying builds none. A bound with room in it would let a regression confined to the
    // cells that need nothing else slip through; this cannot.
    assert_eq!(
        building - verifying,
        cells,
        "building {cells} cells cost {building} and verifying cost {verifying}, so they differ \
         by something other than one allocation for each cell built"
    );
}

#[test]
fn a_second_read_of_the_same_bag_costs_the_same() {
    // The count is the measurement, so it has to be the same every time it is taken.
    let bag = unhex(PROOF_HEX);
    let (_, first) = calls_to_allocate(|| parse_boc(&bag).expect("parses"));
    let (_, second) = calls_to_allocate(|| parse_boc(&bag).expect("parses"));
    assert_eq!(first, second, "reading a bag is not allowed to vary");
}
