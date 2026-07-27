// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Nirapod Labs

//! What a depth a peer chose costs the stack.
//!
//! `MAX_DEPTH` is the only thing bounding how deep a bag may be, and `NET-ADR-012` fixes
//! that it may not be raised because it is a stack-safety bound rather than a memory one.
//! This file is the measurement behind that, because a stack bound nothing measures is a
//! bound nobody can hold a change to.
//!
//! What the stack costs, measured on the fixtures below as the smallest thread each came
//! back on, and what it says:
//!
//! | at the depth limit | debug | release |
//! |---|---:|---:|
//! | parsing a bag | under 32 KiB | under 32 KiB |
//! | parsing it and dropping it | 407 KiB | 103 KiB |
//!
//! Parsing is flat, and its figure is a ceiling rather than a measurement: a platform will
//! not hand out a thread stack below its own minimum and rounds a smaller request up, so the
//! read still came back on every size down to four KiB and the number stops meaning anything
//! before it gets small enough to bisect. What grows with the depth is dropping the result. A
//! cell holds its children, so releasing the last handle on a chain releases the next, and
//! that is a recursion whose depth a peer picked. The existing depth test says the limit
//! stands between a peer and a chain long enough that "walking it takes the stack with it";
//! walking it does not, and this is the correction.
//!
//! Two things follow, and the second is why these are tests rather than a note. Neither
//! figure is close to a default thread, which is 2 MiB in Rust and 8 MiB for a process's
//! first one, so the margin at the limit is about five times in debug and twenty in
//! release. And the failure has no soft form: a stack that runs out aborts, so none of
//! `forbid(unsafe_code)`, the denied panicking helpers, or a `Result` reaches it. A budget
//! that is enforced is the only kind worth stating.
//!
//! The budgets below are stated with room over the measurements rather than against them,
//! so a frame that grows a little is not a failing test, while a cost that grew with the
//! depth by a different factor is.

use ton_net_cell::{AugDict, Augmentation, Builder, CellError, Dict, Slice, Traverse, MAX_BITS};

use crate::hostile::deep_chain;

/// What a bag at the depth limit is allowed to cost, parsed and dropped.
///
/// Measured at 407 KiB in debug and 103 in release, against a quarter of a default thread.
const BAG_BUDGET: usize = 768 << 10;

/// What an augmented dictionary at its deepest is allowed to cost, validated or walked.
///
/// Measured at 1673 KiB to validate and 1466 to walk, both in debug, where the same walks
/// in release take 301 and 254. These recurse where the bag read does not, which is what
/// puts them four times above the bag on the same fixture depth.
const DICT_BUDGET: usize = 3 << 20;

/// Runs `body` on a thread of `stack` bytes and waits for it.
///
/// A thread that runs out of stack aborts the process rather than unwinding, so a failure
/// here is a killed test binary and not a failed assertion. That is the honest shape of the
/// thing being measured, and the panic message names which walk was running.
fn on_a_stack_of(stack: usize, body: impl FnOnce() + Send + 'static) {
    std::thread::Builder::new()
        .stack_size(stack)
        .spawn(body)
        .expect("the thread starts")
        .join()
        .expect("the walk came back");
}

#[test]
fn a_bag_at_the_depth_limit_is_parsed_and_released_inside_its_budget() {
    // Both halves on the small thread, because the cost being held is the whole of what a
    // caller pays for a bag it was handed: reading it, and letting go of it.
    let bag = deep_chain(1023);
    on_a_stack_of(BAG_BUDGET, move || {
        let roots = ton_net_cell::parse_boc(&bag).expect("a bag at the limit parses");
        assert_eq!(roots.len(), 1, "one root");
        // The chain is asserted to be the depth it is named for, on the thread that pays for
        // it, because a bag that came out shallow would cost nothing to release and this
        // budget would hold nothing.
        let root = roots.first().expect("the one root");
        assert_eq!(root.depth(), 1023, "the chain is at the limit");
        drop(roots);
    });
}

#[test]
fn parsing_a_bag_costs_the_same_stack_at_any_depth() {
    // The half that does not grow, held separately so that a read which started carrying its
    // stack on the stack would fail here rather than hide inside the budget above. The
    // shallow bag and the deep one run on the same thread, and it is one the deep one cannot
    // be released on: releasing it wants about four hundred KiB and this is thirty-two.
    //
    // Thirty-two rather than something smaller because a smaller request buys nothing. A
    // platform has a minimum thread stack and rounds up to it, so this test still passed with
    // four KiB written here, which is how the figure was arrived at rather than assumed. What
    // it holds is the shape and not a tight bound: a read that took even thirty bytes a level
    // would want more than this at the depth limit.
    const FLAT: usize = 32 << 10;
    for links in [4usize, 1023] {
        let bag = deep_chain(links);
        on_a_stack_of(FLAT, move || {
            let roots = ton_net_cell::parse_boc(&bag).expect("the bag parses");
            #[allow(clippy::cast_possible_truncation)]
            let want = links as u16;
            let root = roots.first().expect("the one root");
            assert_eq!(root.depth(), want, "the chain is {links} deep");
            // Released out on the caller's stack instead, which is the whole point of the
            // split: this thread pays for the read and nothing else.
            std::mem::forget(roots);
        });
    }
}

/// The summary an augmented dictionary carries here, and the smallest one that makes the
/// fork rebuild in `validate` do real work.
#[derive(Debug, Clone)]
struct Sum;

impl Augmentation for Sum {
    type Extra = u64;

    fn read(&self, slice: &mut Slice<'_>) -> Result<u64, CellError> {
        slice.load_uint(64)
    }

    fn combine(&self, left: &u64, right: &u64) -> Result<u64, CellError> {
        Ok(left.saturating_add(*right))
    }

    fn write(&self, extra: &u64, into: &mut Builder) -> Result<(), CellError> {
        into.store_uint(*extra, 64)?;
        Ok(())
    }
}

/// A comb of `depth` forks: key `i` carries its one set bit at position `i`, so every fork
/// splits a single leaf off and the tree is as deep as it has entries.
///
/// A dictionary cannot be deeper than its key is wide, because a fork spends at least one
/// bit, so `MAX_BITS` forks is the deepest a peer can hand over at all.
fn comb_keys(depth: usize) -> Vec<[u8; 128]> {
    let mut keys = Vec::with_capacity(depth + 1);
    for i in 0..depth {
        let mut key = [0u8; 128];
        key[i / 8] |= 1 << (7 - (i % 8));
        keys.push(key);
    }
    keys.push([0u8; 128]);
    keys
}

fn a_value() -> Builder {
    let mut value = Builder::new();
    value.store_uint(1, 8).expect("a value fits");
    value
}

#[test]
fn the_deepest_dictionary_a_peer_can_send_is_walked_inside_its_budget() {
    // A tree one fork short of the widest key, which is the deepest shape there is: each of
    // these walks descends by recursion, so what is held here is that the recursion at the
    // format's own limit stays inside a stated stack rather than inside whatever the host
    // happened to give the thread.
    let depth = usize::from(MAX_BITS) - 1;
    let keys = comb_keys(depth);

    let plain = {
        let value = a_value();
        Dict::from_items(MAX_BITS, keys.iter().map(|key| (*key, &value))).expect("the comb builds")
    };
    let walked = plain.iter().count();
    assert_eq!(walked, keys.len(), "the walk reached every key");

    let aug = AugDict::from_items(
        Sum,
        MAX_BITS,
        keys.iter().map(|key| (*key, 1u64, a_value())),
    )
    .expect("the augmented comb builds");

    // The fixture is asserted to be the shape it is named for before anything is measured on
    // it. A comb that came out balanced would be about ten forks deep rather than a thousand,
    // every walk below would fit any stack, and all of this would pass having held nothing.
    #[allow(clippy::cast_possible_truncation)]
    let want = depth as u16;
    let root = aug.root().expect("the tree has a root");
    assert_eq!(
        root.depth(),
        want,
        "the comb is {} forks deep, not {want}",
        root.depth()
    );

    let validating = aug.clone();
    on_a_stack_of(DICT_BUDGET, move || {
        validating.validate().expect("the deepest tree validates");
    });

    let walking = aug.clone();
    on_a_stack_of(DICT_BUDGET, move || {
        let mut seen = 0usize;
        walking
            .traverse_extra(|_| {
                seen += 1;
                Traverse::Continue
            })
            .expect("the deepest tree is walked");
        assert!(seen > 0, "the walk visited something");
    });
}
