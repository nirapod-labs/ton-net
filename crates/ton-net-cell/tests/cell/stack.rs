// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Nirapod Labs

//! What a depth a peer chose costs the stack.
//!
//! `MAX_DEPTH` is the only thing bounding how deep a bag may be, and `NET-ADR-012` fixes
//! that it may not be raised because it is a stack-safety bound rather than a memory one.
//! Nothing measured it, so a walk that started costing twice as much per level had nothing
//! to fail.
//!
//! Every figure below is produced by [`measure`] in this file rather than written by hand.
//! It bisects the thread each scenario comes back on, one process per attempt, and prints
//! the table. The figures step in pages, because a platform hands a stack out in whole ones
//! and rounds a smaller request up, which is also why the reading for a flat scenario is a
//! ceiling rather than a measurement.
//!
//! On a 1024-link chain and a 1023-fork comb, both at their formats' limits:
//!
//! | scenario | debug | release |
//! |---|---:|---:|
//! | parse a bag | 32 KiB | 32 KiB |
//! | parse and release it | 416 KiB | 112 KiB |
//! | render it with `Cell::dump` | 304 KiB | 192 KiB |
//! | prove it with `UsageTree::prove` | 880 KiB | 272 KiB |
//! | validate the dictionary | 1712 KiB | 320 KiB |
//! | walk the dictionary | 1504 KiB | 272 KiB |
//! | collect its fork summaries | 1216 KiB | 256 KiB |
//!
//! Reading a bag is the only scenario that is flat. It costs the same at four links and at
//! the limit, because the read loop carries its stack on the heap. Everything else walks a
//! cell per frame and grows with the depth: releasing a tree does, because a cell holds its
//! children and letting go of the last handle on a chain lets go of the next, and so do the
//! per-reference walks `NET-ADR-012` already names, `render`, `prune_cell` and `graft`.
//!
//! [`measure`] prints what it derives as well, because leaving the arithmetic to the prose
//! is the same failure one step along. Against a default thread, which is 2 MiB in Rust and
//! 8 MiB for a process's first, the worst of these scenarios clears by 6.40 times in release
//! and by 1.20 in debug. So a debug build at the limit is inside a default thread and not
//! far inside it.
//!
//! An embedder handing this crate a smaller thread than the default is outside everything
//! measured here. On half a megabyte the dictionary walks abort in debug and all of them
//! come back in release; release does not give way until a quarter of a megabyte, where
//! validating and walking the dictionary go and its fork summaries still come back.
//!
//! The failure has no soft form: a stack that runs out aborts, so `forbid(unsafe_code)`, the
//! denied panicking helpers and a `Result` are all out of the path.
//!
//! The budgets are stated with room over the measurements rather than against them, so a
//! frame that grows a little is not a failing test, while a cost that grew with the depth by
//! a different factor is.

use std::process::Command;

use ton_net_cell::{
    AugDict, Augmentation, Builder, CellError, Dict, Slice, Traverse, UsageTree, MAX_BITS,
    MAX_DEPTH,
};

use crate::hostile::deep_chain;

/// A chain at the depth limit, which `hostile.rs` asserts is a legal bag.
const LINKS: usize = MAX_DEPTH;

/// The deepest comb a peer can hand over: a fork spends at least one key bit, so a
/// dictionary is never deeper than its key is wide.
const FORKS: usize = MAX_BITS as usize;

/// Every scenario, and the stack each is held to.
///
/// Each budget is between 1.68 and 1.89 times the debug figure above, which [`measure`]
/// prints so it is not arithmetic anyone has to redo. That is room enough that a frame
/// growing a little does not fail and tight enough that halving the budget does: each was
/// checked to abort at half in debug, which is what says the number holds something. A
/// release build clears every budget by six times or better, so it is the debug figure each
/// of these is set against. Anything tighter would fail on a host whose pages are a different
/// size rather than on a regression, since the measurement can only resolve to a page.
///
/// Reading a bag is the exception and cannot be graded that way. Its figure is the page
/// floor rather than a cost, so halving it changes nothing;
/// [`parsing_a_bag_costs_the_same_stack_at_any_depth`] is what holds that one, and it is
/// graded by making its thread release the deep bag instead of handing it back.
const SCENARIOS: &[(&str, usize)] = &[
    ("parse", 32 << 10),
    ("release", 768 << 10),
    ("dump", 576 << 10),
    ("prove", 1536 << 10),
    ("validate", 3 << 20),
    ("traverse", 2560 << 10),
    ("forks", 2 << 20),
];

/// The summary the augmented fixture carries. Sixty-four bits, so a fork's rebuilt summary
/// is wider than the label beside it and the combine is not free.
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

/// A comb of `FORKS` forks: key `i` carries its one set bit at position `i`, so every fork
/// splits a single leaf off and the tree is as deep as it has entries.
fn comb_keys() -> Vec<[u8; 128]> {
    let mut keys = Vec::with_capacity(FORKS + 1);
    for i in 0..FORKS {
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

/// The augmented comb, asserted to be the depth it is named for.
///
/// A fixture that came out shallow would clear every budget here having held nothing, so it
/// is checked before anything is measured on it.
fn deep_aug() -> AugDict<Sum> {
    let keys = comb_keys();
    let aug = AugDict::from_items(
        Sum,
        MAX_BITS,
        keys.iter().map(|key| (*key, 1u64, a_value())),
    )
    .expect("the augmented comb builds");
    let root = aug.root().expect("the tree has a root");
    assert_eq!(
        root.depth(),
        MAX_BITS,
        "the comb is {} forks deep, not {MAX_BITS}",
        root.depth()
    );
    aug
}

/// A chain at the limit, asserted to be that deep.
fn deep_bag() -> Vec<u8> {
    let bag = deep_chain(LINKS);
    let roots = ton_net_cell::parse_boc(&bag).expect("a bag at the limit parses");
    let root = roots.first().expect("the one root");
    #[allow(clippy::cast_possible_truncation)]
    let want = LINKS as u16;
    assert_eq!(root.depth(), want, "the chain is at the limit");
    bag
}

/// Builds what `scenario` needs, then runs it on a stack of `stack` bytes.
///
/// A fixture is built out here and moved in, never built inside. Building one parses a bag
/// and releases it, which is one of the scenarios, and doing that on the measured thread
/// would put a 416 KiB floor under every other reading.
fn spawn(scenario: &str, stack: usize) {
    let name = scenario.to_owned();
    match scenario {
        "parse" | "release" | "dump" | "prove" => {
            let bag = deep_bag();
            on_a_stack_of(scenario, stack, move || run_over_a_bag(&name, &bag));
        }
        "validate" | "traverse" | "forks" => {
            let aug = deep_aug();
            on_a_stack_of(scenario, stack, move || run_over_a_dictionary(&name, &aug));
        }
        "plain" => {
            let keys = comb_keys();
            let value = a_value();
            let dict = Dict::from_items(MAX_BITS, keys.iter().map(|key| (*key, &value)))
                .expect("the comb builds");
            on_a_stack_of(scenario, stack, move || {
                assert_eq!(
                    dict.iter().count(),
                    keys.len(),
                    "the walk reached every key"
                );
                std::mem::forget(dict);
            });
        }
        other => panic!("unknown scenario {other}"),
    }
}

/// The scenarios over a chain at the depth limit.
///
/// What is not being measured is leaked rather than dropped, because releasing a deep tree
/// is itself one of the scenarios and would otherwise be added to all the others.
fn run_over_a_bag(scenario: &str, bag: &[u8]) {
    match scenario {
        "parse" => {
            let roots = ton_net_cell::parse_boc(bag).expect("parses");
            std::mem::forget(roots);
        }
        "release" => {
            let roots = ton_net_cell::parse_boc(bag).expect("parses");
            drop(roots);
        }
        "dump" => {
            let roots = ton_net_cell::parse_boc(bag).expect("parses");
            let rendered = roots.first().expect("the one root").dump();
            assert!(!rendered.is_empty(), "the render produced something");
            std::mem::forget(roots);
        }
        "prove" => {
            let roots = ton_net_cell::parse_boc(bag).expect("parses");
            let root = roots.first().expect("the one root").clone();
            let mut usage = UsageTree::new(root.clone());
            let mut at = root.clone();
            loop {
                usage.mark(&at);
                let Some(next) = at.reference(0).cloned() else {
                    break;
                };
                at = next;
            }
            let proof = usage.prove().expect("the chain proves");
            assert_eq!(proof.depth(), root.depth() + 1, "a proof stands one above");
            std::mem::forget((roots, usage, proof, at, root));
        }
        other => panic!("{other} is not a scenario over a bag"),
    }
}

/// The scenarios over the deepest dictionary a peer can send.
fn run_over_a_dictionary(scenario: &str, aug: &AugDict<Sum>) {
    match scenario {
        "validate" => aug.validate().expect("the deepest tree validates"),
        "traverse" => {
            let mut seen = 0usize;
            aug.traverse_extra(|_| {
                seen += 1;
                Traverse::Continue
            })
            .expect("the deepest tree is walked");
            // A fork for each of them and a leaf for each key, which is what a comb is.
            assert_eq!(seen, 2 * FORKS + 1, "the walk visited every node");
        }
        "forks" => {
            let forks = aug.fork_extras().expect("the summaries come back");
            assert_eq!(forks.len(), FORKS, "one summary for each fork");
        }
        other => panic!("{other} is not a scenario over a dictionary"),
    }
}

/// Runs `body` on a thread of `stack` bytes, named so an abort says which one died.
fn on_a_stack_of(name: &str, stack: usize, body: impl FnOnce() + Send + 'static) {
    std::thread::Builder::new()
        .name(name.to_owned())
        .stack_size(stack)
        .spawn(body)
        .expect("the thread starts")
        .join()
        .expect("the walk came back");
}

/// The gate, and the child half of [`measure`].
///
/// A stack that runs out aborts rather than unwinding, so a scenario cannot be bisected
/// inside the process running it. This test is the one process per attempt: under
/// `TON_NET_STACK_HARNESS` it runs the one scenario it is asked for on the stack it is given
/// and its exit status is the answer. Without it, it runs every scenario on its budget, which
/// is what the gate does.
///
/// The switch is a variable of the harness's own rather than the scenario name, so that a
/// scenario left set in a shell narrows the harness and cannot quietly narrow the gate to one
/// walk while still reporting a pass.
#[test]
fn every_walk_stays_inside_its_stack_budget() {
    if std::env::var_os("TON_NET_STACK_HARNESS").is_some() {
        let scenario = std::env::var("TON_NET_STACK_SCENARIO").expect("a scenario to run");
        let kib: usize = std::env::var("TON_NET_STACK_KIB")
            .expect("a stack to try")
            .parse()
            .expect("a number of KiB");
        spawn(&scenario, kib << 10);
        return;
    }

    for (scenario, budget) in SCENARIOS {
        spawn(scenario, *budget);
    }
}

/// The plain dictionary's walk, held apart because it is the one that does not recurse.
///
/// It runs on the stack the flat bag read is held to, over the same tree the recursive walks
/// above want between thirty-eight and fifty-four times that for in debug, and eight to ten
/// in release. That spread is the whole difference between an explicit stack and the
/// machine's.
#[test]
fn the_iterative_dictionary_walk_is_flat_in_depth() {
    spawn("plain", 32 << 10);
}

/// Reading a bag costs the same stack at four links and at the limit.
///
/// Held apart from releasing it so that a read which started carrying its stack on the stack
/// fails here rather than hiding inside the larger budget. The floor is what the platform
/// hands out rather than what is asked for, so what this holds is the shape: a read taking
/// even thirty-three bytes a level would want more than this at the limit.
#[test]
fn parsing_a_bag_costs_the_same_stack_at_any_depth() {
    for links in [4usize, LINKS] {
        let bag = deep_chain(links);
        on_a_stack_of("parse", 32 << 10, move || {
            let roots = ton_net_cell::parse_boc(&bag).expect("the bag parses");
            #[allow(clippy::cast_possible_truncation)]
            let want = links as u16;
            let root = roots.first().expect("the one root");
            assert_eq!(root.depth(), want, "the chain is {links} deep");
            std::mem::forget(roots);
        });
    }
}

/// What a default thread is in Rust, which every multiple below is against.
const DEFAULT_THREAD: usize = 2 << 10;

/// Bisects the stack each scenario comes back on and prints both tables.
///
/// Ignored by default because it spawns on the order of a hundred processes. It is the
/// source of every figure in this file: a number in a comment that nobody can rerun is a
/// number that goes stale without failing anything.
///
/// It prints what it derives as well as what it measured, because leaving the arithmetic to
/// the prose is the same failure one step along. The margin against a default thread and the
/// room a budget has over its figure both went into a comment by hand once and both were
/// wrong there.
#[test]
#[ignore = "a measuring harness, run by hand when a figure needs retaking"]
fn measure() {
    /// A stack is handed out in whole pages, so the search steps in them and the answer is
    /// reported as one. A host whose pages are smaller reports a finer figure for the same
    /// code, which is why a budget here is never set within a page of its measurement.
    const PAGE: usize = 16;

    let exe = std::env::current_exe().expect("this test binary");
    let comes_back = |scenario: &str, kib: usize| {
        Command::new(&exe)
            .args(["--exact", "stack::every_walk_stays_inside_its_stack_budget"])
            .env("TON_NET_STACK_HARNESS", "1")
            .env("TON_NET_STACK_SCENARIO", scenario)
            .env("TON_NET_STACK_KIB", kib.to_string())
            .output()
            .expect("the child runs")
            .status
            .success()
    };

    let mut measured = Vec::new();
    for (scenario, budget) in SCENARIOS {
        let (mut low, mut high) = (PAGE, 4 << 10);
        let mut ever_failed = false;
        while high - low > PAGE {
            let mid = low.midpoint(high) / PAGE * PAGE;
            if comes_back(scenario, mid) {
                high = mid;
            } else {
                low = mid;
                ever_failed = true;
            }
        }
        measured.push((*scenario, high, ever_failed, budget >> 10));
    }

    println!("| scenario | smallest stack it came back on |");
    println!("|---|---:|");
    for (scenario, smallest, _, _) in &measured {
        println!("| {scenario} | {smallest} KiB |");
    }

    println!();
    println!("| scenario | largest that aborts | of a default thread | budget over figure |");
    println!("|---|---:|---:|---:|");
    for (scenario, smallest, ever_failed, budget) in &measured {
        let aborts = if *ever_failed {
            format!("{} KiB", smallest - PAGE)
        } else {
            // Nothing tried was small enough to fail, so this scenario has no threshold to
            // report and its figure is the platform's floor rather than a cost.
            "none tried".to_owned()
        };
        #[allow(
            clippy::cast_precision_loss,
            reason = "every one of these is a count of KiB under a few thousand, so all three are exact in an f64"
        )]
        let (of_default, over_figure) = (
            DEFAULT_THREAD as f64 / *smallest as f64,
            *budget as f64 / *smallest as f64,
        );
        println!("| {scenario} | {aborts} | {of_default:.2}x | {over_figure:.2}x |");
    }
}
