// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Nirapod Labs

//! What handing a wave of cells to several threads costs the allocator.
//!
//! `tests/allocations.rs` counts per thread, and says why: the harness runs its tests side by
//! side, so a count shared between them would report whatever the others happened to be doing.
//! That choice has a consequence it cannot fix from inside itself. A wave wide enough to be
//! split runs on threads the measuring thread never touches, and a per-thread counter cannot
//! see them, so the one path whose cost is a question about threads is the one path that file
//! is blind to. No committed fixture reaches it either: the widest is 1,121 cells and a wave is
//! not split under two full shares of a thousand and twenty-four.
//!
//! So this is a second test target rather than a ninth test over there, and the reason is the
//! isolation a global counter needs. **This binary carries one test.** While its body runs, the
//! only other thread in the process is the harness's own, waiting on the result, so a count
//! every thread adds to is a count of the body and of the workers it started. Adding a second
//! test here would take that argument away.
//!
//! What is measured is a difference rather than a total, so everything a read costs that is not
//! the split cancels. Two bags are read, alike in every way that costs an allocation except one:
//! one carries a leaf wave of two full shares and the other a leaf wave one cell short, which is
//! the width at which the dispatch stops splitting. Their cell counts differ by that one cell,
//! and their allocation counts differ by that cell plus whatever the split cost.
//!
//! There are two things a run of this can establish and it says on the way which one it did.
//! Where the wave is split, the difference is that leaf and what the split cost, and the equality
//! at the end is a reading of the split path. Where it is not, because the `parallel` feature is
//! off or the machine reports a single thread, the difference is the leaf alone and nothing about
//! splitting was measured. The second passes rather than fails, a single core being a legitimate
//! machine, and it reports itself on stderr as it goes: a gate that measured nothing otherwise
//! reads exactly like a gate that measured and found nothing, and those have to be told apart
//! from the log.

use std::alloc::{GlobalAlloc, Layout, System};
use std::hint::black_box;
use std::io::Write;
use std::num::NonZeroUsize;
use std::sync::atomic::{AtomicUsize, Ordering};

use ton_net::cell::{parse_boc, serialize_boc, BocView, Builder, Cell, CellError};

/// Calls to the allocator on every thread since the count was last cleared.
static CALLS: AtomicUsize = AtomicUsize::new(0);

/// Bytes asked for on every thread since the count was last cleared.
static BYTES: AtomicUsize = AtomicUsize::new(0);

/// The system allocator, counting every call that asks it for memory, on whatever thread.
struct Counting;

unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        // Relaxed is the whole ordering these need. Each add is atomic, so no increment is
        // lost, and the reads below happen after the workers are joined, which is what makes
        // their writes visible rather than any ordering asked for here.
        CALLS.fetch_add(1, Ordering::Relaxed);
        BYTES.fetch_add(layout.size(), Ordering::Relaxed);
        System.alloc(layout)
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        System.dealloc(ptr, layout);
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        CALLS.fetch_add(1, Ordering::Relaxed);
        BYTES.fetch_add(new_size, Ordering::Relaxed);
        System.realloc(ptr, layout, new_size)
    }
}

#[global_allocator]
static ALLOCATOR: Counting = Counting;

/// Runs `body` and reports how many times it, and every thread it started, asked for memory.
fn calls_to_allocate<T>(body: impl FnOnce() -> T) -> (T, usize) {
    CALLS.store(0, Ordering::Relaxed);
    let value = body();
    (value, CALLS.load(Ordering::Relaxed))
}

/// Runs `body` and reports how many bytes it, and every thread it started, asked for.
fn bytes_to_allocate<T>(body: impl FnOnce() -> T) -> (T, usize) {
    BYTES.store(0, Ordering::Relaxed);
    let value = body();
    (value, BYTES.load(Ordering::Relaxed))
}

/// The fewest cells a worker is handed, restated here because the dispatch keeps it private.
///
/// A restated constant can drift from the one it copies, and this one is placed so that drift
/// fails rather than passes: the two bags below are cut around it, so a dispatch that moved its
/// floor either splits both of them or neither, and the difference asserted at the end is the
/// difference between splitting and not.
const CELLS_PER_WORKER: usize = 1024;

/// A leaf wave of two full shares, which is the narrowest wave the dispatch splits.
const SPLIT: usize = CELLS_PER_WORKER * 2;

/// The same wave one cell short, which is the widest wave it does not.
const WHOLE: usize = SPLIT - 1;

/// Room for the one leaf by which the two bags differ, where a difference in bytes is bounded.
///
/// Stated well over what a cell of a bag costs to read and build, and well under one copy of the
/// wave, so it absorbs the leaf without absorbing what the bound is there to catch.
const A_LEAF: usize = 1 << 10;

/// A bag whose leaves are one wave and whose forks are the waves above it.
///
/// Every leaf carries its own position, so no two cells of a level are equal and none of them is
/// folded together when the bag is written. The forks take four children each, so the leaf wave
/// is four times the one over it and is the only wave whose width the dispatch has anything to
/// decide about.
fn fan_bag(leaves: usize) -> Vec<u8> {
    let mut level: Vec<Cell> = (0..leaves)
        .map(|index| {
            let mut builder = Builder::new();
            builder
                .store_uint(index as u64, 32)
                .expect("a position fits");
            builder.build().expect("well formed")
        })
        .collect();
    while level.len() > 1 {
        level = level
            .chunks(4)
            .map(|group| {
                let mut builder = Builder::new();
                for child in group {
                    builder.store_ref(child.clone()).expect("a reference fits");
                }
                builder.build().expect("well formed")
            })
            .collect();
    }
    serialize_boc(&level).expect("serializes")
}

/// How many cells a bag holds, read from its header without building anything.
fn cells_in(bag: &[u8]) -> usize {
    BocView::open(bag).expect("the bag opens").cell_count()
}

/// How many workers the dispatch has to choose from for a wave of two full shares.
///
/// Asked of the standard library rather than of the library under test, so a dispatch that
/// stopped asking the machine at all is a disagreement this can report rather than absorb.
fn workers() -> usize {
    std::thread::available_parallelism()
        .map_or(1, NonZeroUsize::get)
        .min(SPLIT / CELLS_PER_WORKER)
}

/// What starting `workers` scoped threads costs, with nothing for them to do.
///
/// The split's own cost has a part in it that belongs to the standard library rather than to
/// this crate: a handle for each worker, and whatever a spawn takes. Writing that as a literal
/// would pin a number nothing here owns, so it is measured in the shape the split uses it, a
/// vector of handles filled from a sized iterator and joined in turn. Each closure holds a
/// borrow, so none of them is the empty type a box costs nothing to hold.
fn calls_to_start(workers: usize) -> usize {
    let borrowed = 0usize;
    let ((), asked) = calls_to_allocate(|| {
        std::thread::scope(|scope| {
            let running: Vec<_> = (0..workers)
                .map(|_| {
                    scope.spawn(|| {
                        black_box(&borrowed);
                    })
                })
                .collect();
            for worker in running {
                worker
                    .join()
                    .expect("a worker with nothing to do cannot fail");
            }
        });
    });
    asked
}

#[test]
fn a_split_wave_is_written_into_one_buffer() {
    let split = fan_bag(SPLIT);
    let whole = fan_bag(WHOLE);
    let (wide, narrow) = (cells_in(&split), cells_in(&whole));
    assert_eq!(
        wide - narrow,
        1,
        "the two bags are {wide} and {narrow} cells, so they differ by more than the one leaf \
         that decides whether the leaf wave is split"
    );

    // Read once before anything is counted. The dispatch asks the machine how many threads it
    // has at most once in a process and keeps the answer, so the first bag wide enough to ask
    // would otherwise carry a cost no later read pays, and a measurement that only the first
    // read pays is not one.
    black_box(parse_boc(&split).expect("the split bag parses"));
    black_box(parse_boc(&whole).expect("the whole bag parses"));

    let workers = workers();
    let splits = cfg!(feature = "parallel") && workers > 1;

    // A run with no split in it holds the extra leaf and nothing else, which is a true statement
    // and an empty one, so it says so where it can be read afterwards. Failing instead would be
    // wrong: the feature is off by default and a machine with one thread is a machine this
    // library is for. Going quiet would be worse, because a gate that measured nothing looks
    // from the outside exactly like a gate that measured and found nothing. Written to the
    // process's own stderr rather than through `eprintln!`, which the harness captures and then
    // drops for a test that passed.
    if !splits {
        let why = if cfg!(feature = "parallel") {
            "this machine reports one thread"
        } else {
            "the parallel feature is off"
        };
        let _ = writeln!(
            std::io::stderr(),
            "split_allocations: {why}, so no wave was split and what a split costs went \
             unmeasured. What this run establishes is the one extra leaf alone."
        );
    }

    // What the split is allowed to cost: the handles and the spawns, which belong to the
    // standard library, and one buffer for the wave's outcomes, which is this crate's. Nothing
    // per worker beyond the spawn, and nothing at all per cell. A worker collecting its own
    // outcomes costs one more for each of them, and merging those into a list that cannot be
    // sized ahead of itself costs a further one for every time that list doubles.
    let allowed = if splits {
        calls_to_start(workers) + 1
    } else {
        0
    };

    let (_, on_split) = calls_to_allocate(|| parse_boc(&split).expect("the split bag parses"));
    let (_, on_whole) = calls_to_allocate(|| parse_boc(&whole).expect("the whole bag parses"));
    let apart = on_split
        .checked_sub(on_whole)
        .expect("the wider bag cannot ask for less than the narrower one");
    assert_eq!(
        apart,
        allowed + 1,
        "reading a bag whose leaf wave is split asked {on_split} times and one whose leaf wave \
         is not asked {on_whole}, which is {apart} apart where the extra leaf and the split \
         together account for {}",
        allowed + 1
    );

    // The same reading a second time, because a figure that moves between two reads of one bag
    // is not a measurement.
    let (_, again) = calls_to_allocate(|| parse_boc(&split).expect("the split bag parses"));
    assert_eq!(
        again, on_split,
        "reading the split bag twice asked {on_split} times and then {again}"
    );

    // And the same difference in bytes, which is the quantity a second copy of every outcome
    // shows up in and a count of calls barely does: a list that doubles its way to the length
    // of the wave asks a handful of times for several times the bytes. One buffer holds the
    // wave's outcomes once; a list per worker plus a merged list that grew into it holds them
    // three times over, so a bound at twice the wave separates the two whichever way the
    // spawns fall. The extra leaf is under the same bound rather than beside it, at a size
    // stated well over what one cell of a bag costs and well under one copy of the wave.
    let outcome = size_of::<(usize, Result<Option<Cell>, CellError>)>();
    let (_, bytes_on_split) = bytes_to_allocate(|| parse_boc(&split).expect("parses"));
    let (_, bytes_on_whole) = bytes_to_allocate(|| parse_boc(&whole).expect("parses"));
    let bytes_apart = bytes_on_split.saturating_sub(bytes_on_whole);
    let ceiling = A_LEAF + if splits { 2 * SPLIT * outcome } else { 0 };
    assert!(
        bytes_apart < ceiling,
        "reading the split bag asked for {bytes_apart} bytes more than the bag that is not \
         split, which is at or above the {ceiling} that a leaf and two copies of a {SPLIT} \
         cell wave take"
    );
}
