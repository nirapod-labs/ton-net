// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Nirapod Labs

//! What reading a bag of cells, and walking a dictionary, cost the allocator.
//!
//! Wall-clock timing on the machine this was written on swings by tens of percent between
//! runs of identical code, which is enough to hide a real regression and enough to invent
//! one. A count does not move with the weather: reading the same bag calls the allocator the
//! same number of times every run, and that count is what the memory a
//! large bag needs is proportional to. So the layout is held to a count rather than a clock.
//!
//! What the counts say today, on the captured mainnet fixtures:
//!
//! | bag | cells | building | verifying |
//! |---|---:|---:|---:|
//! | account proof | 45 | 94 | 49 |
//! | basechain block | 1121 | 2015 | 894 |
//!
//! One of those per cell is the cell itself. The other is the hashes above the lowest, which
//! only a cell significant at more than one level has, and 886 of the block's 1121 cells are.
//! A pruned branch carries a mask of its own and the mask reaches its ancestors, losing a level
//! at each Merkle cell above it, which is why 886 of the 1121. Nothing else in a read is per
//! cell.
//!
//! The counts are taken on the thread the read runs on, which is where the whole of these
//! reads happens. A wave of cells is split across threads once it holds twice
//! `CELLS_PER_WORKER`, and neither fixture carries that many cells in total, so no wave of
//! either leaves this thread and none of these counts goes anywhere it would not be seen.
//!
//! A dictionary is measured the same way against a different quantity. A descent reads one edge
//! label per level, so the question there is whether a lookup costs the allocator anything per
//! level. It does not: a lookup is one call, the vector the caller's key bytes are spread into,
//! whether the tree is four forks deep or ten. A walk is one call for each entry, the key vector
//! it hands back, and a few besides for the stack it carries.
//!
//! A write is counted against the forks it rebuilds rather than the levels it reads. A set and a
//! remove over ten forks ask thirty-seven times each, and ask exactly the same on a tree of that
//! depth whose forks carry no label between them, which is the property held below: a write costs
//! what its forks cost to rebuild, and the labels read on the way cost nothing.
//!
//! Three quantities come off the one allocator and they answer different questions. A call count
//! and a byte sum are both cumulative: they rise on every request and never fall, so what they
//! report is what a body asked for across the whole of its run. What that body holds at one
//! moment is a different number and it needs the release side counted too, so `dealloc` debits
//! what `alloc` credited and `realloc` does both. The high-water mark of that difference is the
//! peak, and it is the quantity NET-ADR-012 states a budget against: a bound on what a parse
//! holds while it runs is not a bound on what it asked for on the way.
//!
//! **The peak is per thread, and it is exact only for a body that releases on the thread it took
//! from.** A block credited on one thread and released on another debits a counter that never
//! credited it, and the live figure stops at zero rather than going below, so such a body reads
//! low from that point on. Every body measured in this file takes and releases on the thread it
//! runs on, which is the same scope the counts above are stated at and for the same reason: no
//! bag here is wide enough for a wave to leave this thread.
//!
//! Counting them at all means installing a global allocator, and a global allocator means
//! `unsafe`. That is why this is a test binary and not the library: the library forbids
//! unsafe code and goes on forbidding it, and a test binary is a crate of its own.

use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;
use std::hint::black_box;

use ton_net::cell::{parse_boc, serialize_boc, BocView, Builder, Dict, Lookup};

thread_local! {
    /// Calls to the allocator on this thread since the count was last cleared.
    ///
    /// Per thread rather than global because the test harness runs tests side by side, and a
    /// count shared between them would report whatever the others happened to be doing.
    static CALLS: Cell<usize> = const { Cell::new(0) };

    /// Bytes asked for on this thread since the count was last cleared.
    ///
    /// A count of calls cannot see a reservation, because asking once for a megabyte and once
    /// for a byte are both one call. Where the property being held is that a read takes memory
    /// in proportion to the bag it was handed, the size is the quantity and the count is not.
    static BYTES: Cell<usize> = const { Cell::new(0) };

    /// Bytes this thread has taken and not yet released, since the count was last cleared.
    ///
    /// The counterpart of [`BYTES`] with the release side in it. A sum that only rises reports
    /// the same figure for a body holding a megabyte throughout and a body taking a kilobyte a
    /// thousand times over, and a budget is a statement about the first of those.
    static LIVE: Cell<usize> = const { Cell::new(0) };

    /// The largest [`LIVE`] has reached since the count was last cleared.
    ///
    /// Read at the end rather than sampled, so no moment of the body is missed: every credit
    /// compares against this and raises it, which is the only place the figure can move.
    static PEAK: Cell<usize> = const { Cell::new(0) };
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

/// Records the size of one request, on the same terms as [`count`].
fn record(bytes: usize) {
    let _ = BYTES.try_with(|counter| counter.set(counter.get().saturating_add(bytes)));
}

/// Adds a block this thread now holds, and raises the peak if it is the most so far.
fn credit(bytes: usize) {
    let _ = LIVE.try_with(|live| {
        let held = live.get().saturating_add(bytes);
        live.set(held);
        let _ = PEAK.try_with(|peak| {
            if held > peak.get() {
                peak.set(held);
            }
        });
    });
}

/// Removes a block this thread no longer holds.
///
/// Saturating rather than wrapping, because a block released here that was taken before the
/// counter was cleared, or on another thread, has no credit to remove: the live figure stops at
/// nothing rather than passing under it, which is the scope the module documentation states.
fn debit(bytes: usize) {
    let _ = LIVE.try_with(|live| live.set(live.get().saturating_sub(bytes)));
}

unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        count();
        record(layout.size());
        let taken = System.alloc(layout);
        // A request that failed is a request all the same, so the call and the size are
        // recorded above either way. Nothing is held by it, so the live figure is not.
        if !taken.is_null() {
            credit(layout.size());
        }
        taken
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        debit(layout.size());
        System.dealloc(ptr, layout);
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        // A vector that outgrows itself asks for memory again, which is a cost worth counting
        // whether or not the old block could be extended in place.
        count();
        record(new_size);
        let moved = System.realloc(ptr, layout, new_size);
        // The old block is gone and the new one is held only where the move succeeded. A
        // realloc that failed left the old block where it was, so neither side moves.
        if !moved.is_null() {
            debit(layout.size());
            credit(new_size);
        }
        moved
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

/// Runs `body` and reports how many bytes it asked the allocator for.
fn bytes_to_allocate<T>(body: impl FnOnce() -> T) -> (T, usize) {
    BYTES.with(|counter| counter.set(0));
    let value = body();
    let counted = BYTES.with(Cell::get);
    (value, counted)
}

/// Runs `body` and reports the most bytes it held at once.
///
/// The live count starts at nothing rather than at what this thread already holds, so the figure
/// is what `body` added at its widest and not the process's residency. Whatever `body` returns is
/// still held when the peak is read, so a body handing back its result is measured with that
/// result inside the figure.
fn peak_bytes<T>(body: impl FnOnce() -> T) -> (T, usize) {
    LIVE.with(|counter| counter.set(0));
    PEAK.with(|counter| counter.set(0));
    let value = body();
    let reached = PEAK.with(Cell::get);
    (value, reached)
}

/// Headroom over what a workload costs beyond the thing its cost is counted against.
///
/// For a bag read, measured at eight, which the read path accounts for one at a time: the bag's
/// buffer, the header's root list, the raw cells, the heights, the two vectors the wave plan is
/// held in, the slots the cells are built into, and the roots. For a dictionary walk it is the
/// stack the walk carries as it descends, measured at four. The bounds below are stated with
/// room over both rather than against either, so that a vector growing one step differently is
/// not a failing test, while anything per cell or per entry still is.
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

/// One block of a size chosen so nothing else in a measurement is near it.
///
/// A vector of bytes asks for exactly its capacity, so a body built out of these holds a figure
/// known from the source rather than read off the instrument being tested. A megabyte is far
/// above the handful of words a `Vec` header or a test harness costs, so a stray allocation
/// inside the body would have to be enormous to move the equalities below.
const BLOCK: usize = 1 << 20;

#[test]
fn what_a_body_holds_is_not_what_it_asked_for() {
    // Two blocks of the same size, the second taken after the first is released. The demand is
    // both of them and the residency is one, and a counter that never debits reports the demand
    // for both questions. This is the whole of what the live count adds, so it is held as an
    // equality on each side rather than as a comparison between them.
    let taken_in_turn = || {
        drop(black_box(Vec::<u8>::with_capacity(BLOCK)));
        drop(black_box(Vec::<u8>::with_capacity(BLOCK)));
    };

    let ((), asked) = bytes_to_allocate(taken_in_turn);
    assert_eq!(
        asked,
        BLOCK * 2,
        "two blocks of {BLOCK} bytes were asked for one after the other"
    );

    let ((), peak) = peak_bytes(taken_in_turn);
    assert_eq!(
        peak, BLOCK,
        "the second block was taken after the first was released, so one was ever held"
    );

    // And the same instrument on a body that does hold both at once, which is the case a peak
    // stuck at the size of one block would pass just as happily.
    let ((), peak) = peak_bytes(|| {
        let first = black_box(Vec::<u8>::with_capacity(BLOCK));
        let second = black_box(Vec::<u8>::with_capacity(BLOCK * 2));
        drop(black_box((first, second)));
    });
    assert_eq!(
        peak,
        BLOCK * 3,
        "a block and one twice its size, held together, are three blocks held"
    );
}

#[test]
fn a_peak_of_the_same_read_is_the_same() {
    // The peak is a measurement, so it is held to what NET-ADR-012 holds a count to: a figure
    // that moves between two reads of one bag is not one. A body that returns its result has
    // that result inside the figure, so `parse_boc` is measured with its roots held.
    let bag = unhex(BLOCK_HEX);
    let (_, first) = peak_bytes(|| parse_boc(&bag).expect("parses"));
    let (_, second) = peak_bytes(|| parse_boc(&bag).expect("parses"));
    assert_eq!(first, second, "what a read holds is not allowed to vary");
}

#[test]
fn a_read_asks_for_more_than_it_holds() {
    // The two figures part on whatever a read takes and releases before it returns, and one
    // thing it does that to is known by name: the height of every cell is a machine word each,
    // read to plan the waves and released before a cell is built. So the demand stands at least
    // that far above the residency, and a peak that had quietly become another cumulative sum
    // would sit exactly on it instead.
    let bag = unhex(BLOCK_HEX);
    let cells = cells_in(&bag);

    let (_, asked) = bytes_to_allocate(|| parse_boc(&bag).expect("parses"));
    let (_, peak) = peak_bytes(|| parse_boc(&bag).expect("parses"));

    let released = asked
        .checked_sub(peak)
        .expect("a read cannot hold more than it asked for");
    assert!(
        released >= cells * size_of::<usize>(),
        "reading {cells} cells asked for {asked} bytes and held {peak} at once, which parts by \
         {released} and so by less than the word per cell the heights take"
    );
}

/// A 256-bit key whose `forks` significant bits sit at every other position, counting the
/// value `index` out over them.
///
/// The shape matters. A dictionary over keys counting up in the usual way is dense at the
/// bottom, and a dense fork shares no bits with its sibling, so its label is empty. An empty
/// label asks the allocator for nothing whichever way it is held, a vector that reserves
/// nothing and takes nothing having no reason to, so that shape shows almost none of what a
/// label costs.
/// Spreading the significant bits with a zero between each gives every fork on the path a
/// label of one bit and the leaf a label of the zeros that are left, so a tree `forks` deep
/// reads `forks + 1` labels on the way to a leaf.
fn spread_key(index: u32, forks: usize) -> [u8; 32] {
    let mut key = [0u8; 32];
    for bit in 0..forks {
        if (index >> (forks - 1 - bit)) & 1 == 1 {
            let at = 2 * bit + 1;
            key[at / 8] |= 1 << (7 - (at % 8));
        }
    }
    key
}

/// Every key of a tree `forks` deep, and the dictionary holding them.
fn spread_dict(forks: usize) -> (Dict, Vec<[u8; 32]>) {
    let keys: Vec<[u8; 32]> = (0..1u32 << forks).map(|i| spread_key(i, forks)).collect();
    let mut value = Builder::new();
    value.store_uint(0xdead_beef, 32).expect("a value fits");
    let dict = Dict::from_items(256, keys.iter().map(|key| (*key, &value))).expect("builds");
    (dict, keys)
}

#[test]
fn a_dictionary_lookup_costs_one_allocation_however_deep_the_tree() {
    // The one call is the vector the caller's key bytes are spread into, which a lookup makes
    // once. The labels a descent reads on the way down are held inline and cost nothing, and
    // that is what the three depths are here to show: a label held on the heap would put the
    // depth into this number, and the deepest tree here is six forks deeper than the
    // shallowest.
    for forks in [4usize, 8, 10] {
        let (dict, keys) = spread_dict(forks);
        let key = keys
            .get(keys.len() / 2)
            .copied()
            .expect("a key in the middle");

        let (found, asked) = calls_to_allocate(|| dict.get(&key).expect("the lookup runs"));
        assert!(matches!(found, Lookup::Found(_)), "the key was stored");
        assert_eq!(
            asked, 1,
            "a lookup down {forks} forks asked the allocator {asked} times"
        );

        // A key that is not there but walks the same edges, so it has to cost the same: it
        // agrees with a stored key down every fork and parts from it inside the leaf's own
        // label. The bit it adds sits at an even position, which no spread key ever sets.
        let mut absent = key;
        let at = 2 * forks;
        absent[at / 8] |= 1 << (7 - (at % 8));
        let (missed, asked) = calls_to_allocate(|| dict.get(&absent).expect("the lookup runs"));
        assert_eq!(missed, Lookup::Absent);
        assert_eq!(
            asked, 1,
            "a lookup that finds nothing down {forks} forks asked the allocator {asked} times"
        );
    }
}

/// A 256-bit key whose `forks` significant bits sit at the top, counting the value `index`
/// out over them.
///
/// The counterpart to [`spread_key`] and the control for it. Consecutive significant bits leave
/// every fork on the path sharing nothing with its sibling, so every interior label is empty and
/// only the leaf carries one, where the spread shape gives every edge a label. A path down this
/// tree passes the same number of forks as one down the spread tree of the same depth, which is
/// what makes what the two cost comparable.
fn dense_key(index: u32, forks: usize) -> [u8; 32] {
    let mut key = [0u8; 32];
    for bit in 0..forks {
        if (index >> (forks - 1 - bit)) & 1 == 1 {
            key[bit / 8] |= 1 << (7 - (bit % 8));
        }
    }
    key
}

/// Every key of a dense tree `forks` deep, and the dictionary holding them.
fn dense_dict(forks: usize) -> (Dict, Vec<[u8; 32]>) {
    let keys: Vec<[u8; 32]> = (0..1u32 << forks).map(|i| dense_key(i, forks)).collect();
    let mut value = Builder::new();
    value.store_uint(0xdead_beef, 32).expect("a value fits");
    let dict = Dict::from_items(256, keys.iter().map(|key| (*key, &value))).expect("builds");
    (dict, keys)
}

/// A middle key of a tree, and a value to store under it.
fn a_key_and_a_value(keys: &[[u8; 32]]) -> ([u8; 32], Builder) {
    let mut value = Builder::new();
    value.store_uint(0x0c0f_fee0, 32).expect("a value fits");
    (
        keys.get(keys.len() / 2)
            .copied()
            .expect("a key in the middle"),
        value,
    )
}

#[test]
fn a_write_costs_its_forks_and_nothing_for_the_labels_along_the_way() {
    // A set and a remove rebuild every fork they descended through, so what they cost is per
    // fork, and a label they read on the way is not allowed to add to it. The two trees here
    // are the same depth and differ in their labels: the spread tree carries one at every
    // edge, the dense tree only at its leaves. A label read back onto the heap would cost a
    // call at each edge the one has and the other does not, so the two counts would part by
    // the depth rather than agreeing exactly.
    const FORKS: usize = 10;
    // The shallower tree the growth below is read against, and what a rebuilt fork is allowed
    // to cost: a handful of calls, held to four, and nothing per label.
    const SHALLOW: usize = 4;
    const PER_FORK: usize = 4;

    let (spread, spread_keys) = spread_dict(FORKS);
    let (dense, dense_keys) = dense_dict(FORKS);

    let cost = |dict: &Dict, keys: &[[u8; 32]]| -> (usize, usize) {
        let (key, value) = a_key_and_a_value(keys);
        let mut writing = dict.clone();
        let ((), set) = calls_to_allocate(|| writing.set(&key, &value).expect("sets"));
        let mut removing = dict.clone();
        let (_, removed) = calls_to_allocate(|| removing.remove(&key).expect("removes"));
        (set, removed)
    };

    let (spread_set, spread_remove) = cost(&spread, &spread_keys);
    let (dense_set, dense_remove) = cost(&dense, &dense_keys);
    assert_eq!(
        spread_set, dense_set,
        "a set over {FORKS} forks asked {spread_set} times where every edge carries a label \
         and {dense_set} where only the leaf does"
    );
    assert_eq!(
        spread_remove, dense_remove,
        "a remove over {FORKS} forks asked {spread_remove} times where every edge carries a \
         label and {dense_remove} where only the leaf does"
    );

    // The same read the other way round: what a write costs has to grow with the forks it
    // rebuilds and with nothing else, so six more forks may cost at most twenty-four more. A
    // vector taken at every level would add one for each of the six on top of that, whether
    // or not the level carried a label, which the two counts above agreeing would not catch.
    let (shallow, shallow_keys) = spread_dict(SHALLOW);
    let (shallow_set, shallow_remove) = cost(&shallow, &shallow_keys);
    let allowed = (FORKS - SHALLOW) * PER_FORK;
    assert!(
        spread_set - shallow_set <= allowed,
        "a set cost {shallow_set} over {SHALLOW} forks and {spread_set} over {FORKS}, which is \
         more than {PER_FORK} calls for each fork the deeper one rebuilds"
    );
    assert!(
        spread_remove - shallow_remove <= allowed,
        "a remove cost {shallow_remove} over {SHALLOW} forks and {spread_remove} over {FORKS}, \
         which is more than {PER_FORK} calls for each fork the deeper one rebuilds"
    );
}

#[test]
fn walking_a_dictionary_costs_one_allocation_for_each_key_it_hands_back() {
    // A walk carries the key bits spelled out above each node it has still to visit, and it
    // holds them inline, so what it costs is the key vector it hands the caller per entry and
    // nothing besides. The tree is the deep-labelled shape again: every node on it carries a
    // label, so a walk that read those onto the heap would cost several calls an entry rather
    // than one.
    const FORKS: usize = 10;
    let (dict, keys) = spread_dict(FORKS);

    let (walked, asked) = calls_to_allocate(|| dict.iter().count());
    assert_eq!(walked, keys.len(), "the walk reached every key");
    assert!(
        asked <= walked + SLACK,
        "walking {walked} entries asked the allocator {asked} times, which is more than the \
         key each one hands back"
    );
}

/// What a bag takes to read is proportional to the bag, including its root list.
///
/// A root list is reserved from a count the header states, before an index of it has been
/// read. Two bounds stand in front of that reservation and they answer different questions.
/// The cell ceiling caps it at a constant, which stops a bag naming four billion roots. It
/// does not stop a small bag naming the ceiling, because a constant is not proportional to
/// anything: twenty-one bytes may name a hundred and thirty thousand roots and every one of
/// them is under the ceiling. What answers that is the byte check beside it, which holds the
/// list to the bytes the bag actually carries for it.
///
/// This is measured in bytes rather than calls because the failure is one call asking for a
/// megabyte, and a count of calls cannot tell that from one call asking for eight.
#[test]
fn a_small_bag_naming_many_roots_reserves_nothing_for_them() {
    // Magic, four-byte references, one-byte offsets, one cell, 131,071 roots, no absent
    // cells, a two-byte cell area, and then only two bytes left, which is far less than a
    // root list of that length needs. Every field is inside its own bound; the bag is
    // refused because it does not carry what it says it does.
    let mut bag = Vec::from(*b"\xb5\xee\x9c\x72");
    bag.push(0x04);
    bag.push(0x01);
    bag.extend_from_slice(&1u32.to_be_bytes());
    bag.extend_from_slice(&131_071u32.to_be_bytes());
    bag.extend_from_slice(&0u32.to_be_bytes());
    bag.push(0x02);
    bag.extend_from_slice(&[0x00, 0x00]);
    assert_eq!(
        bag.len(),
        21,
        "the bag is the size the reasoning above assumes"
    );

    let (read, bytes) = bytes_to_allocate(|| parse_boc(&bag));
    assert!(
        read.is_err(),
        "a bag that cannot carry its root list is refused"
    );

    // A reservation for 131,071 roots is 131,071 pointers, which is a megabyte on a 64-bit
    // target. The bound below is far under that and far over what refusing costs, so it
    // fails on the reservation and not on an allocator that moved by a few bytes.
    assert!(
        bytes < 4096,
        "refusing a 21 byte bag asked the allocator for {bytes} bytes, so the root list was \
         reserved before the bag was held to carrying it"
    );
}
