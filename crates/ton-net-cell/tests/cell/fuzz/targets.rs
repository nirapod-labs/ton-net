// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Nirapod Labs

//! The targets: one hostile byte string in, one set of boundary properties checked.
//!
//! Every target is `fn(&[u8])` and reads nothing but that slice, so the driver above can be
//! replaced without touching any of them. A target that needs choices beyond the bag, which
//! read to make or which key width to open a dictionary at, takes them from a stream seeded
//! by the input itself rather than from the driver, which keeps the input the whole of the
//! case.
//!
//! A target returns early on an error. The error is the sound outcome: `CellError` is what
//! the reader promises for anything it will not accept, and there is nothing further to
//! check about a bag that was refused. What each target checks is the other outcome, where
//! the reader accepted something and a caller is now holding it.

use std::collections::HashMap;

use ton_net_cell::{
    parse_boc, serialize_boc, AugDict, Augmentation, BocView, Builder, Cell, CellError, Dict,
    LazyBoc, PfxDict, Slice, MAX_CELLS, MAX_DEPTH,
};

use super::{distinct_cells, Rng};

/// How many of a bag's cells a read target drives.
///
/// A whole block is over a thousand cells, and a script over each is a script over the same
/// reads. Taking a prefix keeps a case proportional to a case rather than to the largest
/// fixture.
const CELLS_READ: usize = 24;

/// How many scripted reads each cell gets.
const READS_PER_CELL: usize = 24;

/// The key widths a dictionary target opens a cell at.
///
/// The four TON uses, and the ones on either side of a label length field changing width,
/// which is where a label decode splits.
const KEY_WIDTHS: [u16; 10] = [0, 1, 7, 8, 15, 16, 32, 64, 256, 267];

/// How many entries a dictionary walk is allowed before the target stops it.
///
/// Nothing in the crate bounds this walk, and a bag whose forks share one child names two
/// entries per cell, so a few hundred bytes describe a walk no run finishes. The cap is the
/// harness holding itself to a budget the code under test does not impose; `docs/fuzzing.md`
/// records how long the longest walk in a run gets before this stops it.
const WALK_CAP: usize = 4_096;

/// The longest chain of references under `roots`, which is the number `MAX_DEPTH` bounds.
///
/// `Cell::depth` is a different number and is not the one to check here. A pruned branch
/// answers with the depth of the subtree it stands in for, and that value is read out of the
/// branch's own body, so a bag of one cell reports whatever depth its two body bytes spell.
/// The parser bounds the graph it built, which is what keeps a later walk or drop off the
/// stack, so the check has to walk that graph.
///
/// Iterative and memoised on the representation hash, because the bound is what is under
/// test: a recursive walk would meet the stack before the assertion.
fn reference_depth(roots: &[Cell]) -> usize {
    let mut done: HashMap<[u8; 32], usize> = HashMap::new();
    let mut stack: Vec<(Cell, bool)> = roots.iter().map(|cell| (cell.clone(), false)).collect();
    let mut deepest = 0;

    while let Some((cell, expanded)) = stack.pop() {
        let key = *cell.repr_hash();
        if done.contains_key(&key) {
            continue;
        }
        if expanded {
            let depth = cell
                .refs()
                .iter()
                .map(|child| done.get(child.repr_hash()).copied().unwrap_or(0) + 1)
                .max()
                .unwrap_or(0);
            deepest = deepest.max(depth);
            done.insert(key, depth);
        } else {
            stack.push((cell.clone(), true));
            stack.extend(cell.refs().iter().map(|child| (child.clone(), false)));
        }
    }
    deepest
}

/// `parse_boc` over arbitrary bytes, the top of the untrusted path.
///
/// What is checked is the shape of what came back: `MAX_DEPTH` over the reference graph, the
/// stored bytes of each cell against its bit count, and the round trip that says the bag can
/// be written again as the same cells. `MAX_CELLS` is not checked here. A bag stores each
/// distinct cell once and this target counts the distinct cells it got back, which is at most
/// the count the header stated, so the count is bounded before this sees it. The door that can
/// see it is `header`, which reads the stated count itself.
pub(super) fn bag_of_cells(bytes: &[u8]) -> bool {
    let Ok(roots) = parse_boc(bytes) else {
        return false;
    };
    assert!(!roots.is_empty(), "a bag parsed to no roots at all");

    let cells = distinct_cells(&roots);
    let deepest = reference_depth(&roots);
    assert!(
        deepest <= MAX_DEPTH,
        "a chain of {deepest} references parsed past the {MAX_DEPTH} depth limit"
    );

    // A cell's bit count and reference count are bounded by the types that carry them rather
    // than by a check the reader performs: `bit_len` reads a byte, halves it, multiplies by
    // eight and adds at most seven, which lands on `MAX_BITS` at its widest, and a cell holds
    // its references in an enum whose widest variant has `MAX_REFS` slots. Asserting either
    // here would be asserting arithmetic, so what is left is the one property of a cell's
    // stored bytes that the reader does decide.
    for cell in &cells {
        // The stored bytes are the ones the bit count needs and no more, so a cell carries
        // no byte the representation hash covers and the bit count does not account for.
        assert_eq!(
            cell.data().len(),
            usize::from(cell.bit_len()).div_ceil(8),
            "a cell's stored bytes do not follow from its bit count"
        );
    }

    let written = serialize_boc(&roots).expect("a bag that parsed serializes");

    let back = parse_boc(&written).expect("a bag this crate wrote parses back");
    assert_eq!(
        back.len(),
        roots.len(),
        "a round trip changed the root count"
    );
    for (again, root) in back.iter().zip(&roots) {
        assert_eq!(
            again.repr_hash(),
            root.repr_hash(),
            "a round trip changed a cell's identity"
        );
    }
    assert_eq!(
        serialize_boc(&back).expect("a bag this crate wrote serializes"),
        written,
        "serializing the same cells twice gave two different bags"
    );
    true
}

/// The header reader, and the five readers that stand on it.
///
/// `parse_boc`, `BocView::materialize`, `BocView::verify`, `BocView::cell` and `LazyBoc` read
/// one bag five ways. They share a header reader and a cell reader and diverge in what they
/// keep, so an input where they disagree is an input where one of them has a bound the others
/// do not.
///
/// Of those five, this is the one that stops at the header, before a cell is built, which is
/// where the counts a bag states about itself are still statements rather than things
/// already read.
pub(super) fn header(bytes: &[u8]) -> bool {
    let opened = BocView::open(bytes);
    let parsed = parse_boc(bytes);

    if let Err(refused) = &opened {
        assert_eq!(
            parsed.as_ref().err(),
            Some(refused),
            "the header reader refused a bag parse_boc did not"
        );
        return false;
    }
    let Ok(view) = opened else {
        return false;
    };

    assert!(
        view.cell_count() <= MAX_CELLS,
        "a header declaring {} cells opened past the {MAX_CELLS} cell limit",
        view.cell_count()
    );
    // Every cell costs at least its two descriptor bytes, so a count the remaining bytes
    // could not hold is a count nothing behind it can honour. The header reader refuses one
    // before it allocates for it, and this is the door that can see that: the count a view
    // reports is the one the header stated, so a view that opened on a count the bytes
    // cannot hold is a refusal that did not happen. Counting the cells of a bag that already
    // parsed would not see it, because a parsed bag has read those two bytes per cell.
    assert!(
        view.cell_count() * 2 <= bytes.len(),
        "a header of a {} byte bag declared {} cells",
        bytes.len(),
        view.cell_count()
    );
    // Two root entries may name one cell, so the cell count does not bound the root list.
    // Two other things do, and both are asserted: the ceiling, which is `MAX_CELLS` here
    // because `BocView::open` takes no options, and the bytes the bag carries for the list,
    // which is what keeps the reservation proportional to the input rather than to a
    // constant.
    assert!(
        view.root_count() >= 1 && view.root_count() <= MAX_CELLS,
        "a header declared {} roots past the {MAX_CELLS} ceiling",
        view.root_count()
    );
    assert!(
        view.root_count() <= bytes.len(),
        "a header of a {} byte bag declared {} roots, so the list it reserves for is not \
         bounded by the bytes behind it",
        bytes.len(),
        view.root_count()
    );
    assert!(
        view.cell_area_len() <= bytes.len(),
        "a header claimed a {} byte cell area inside {} bytes",
        view.cell_area_len(),
        bytes.len()
    );

    let materialized = view.materialize();
    match (&materialized, &parsed) {
        (Ok(built), Ok(roots)) => {
            assert_eq!(
                built.len(),
                roots.len(),
                "two readers found different roots"
            );
            for (one, other) in built.iter().zip(roots) {
                assert_eq!(
                    one.repr_hash(),
                    other.repr_hash(),
                    "two readers gave one bag two identities"
                );
            }
        }
        (Err(one), Err(other)) => assert_eq!(one, other, "two readers refused a bag differently"),
        _ => panic!("materialize and parse_boc disagree on whether a bag reads"),
    }

    match (view.verify(), &materialized) {
        (Ok(hashes), Ok(built)) => {
            assert_eq!(
                hashes.len(),
                built.len(),
                "verify found a different root count"
            );
            for (hash, cell) in hashes.iter().zip(built) {
                assert_eq!(
                    hash,
                    cell.repr_hash(),
                    "the summary reader and the graph reader disagree on a root"
                );
            }
        }
        (Err(one), Err(other)) => assert_eq!(&one, other, "two readers refused a bag differently"),
        _ => panic!("verify and materialize disagree on whether a bag reads"),
    }

    // The fifth reader stops between the two: it reads the bag once, as `materialize` does,
    // and then builds a cell at a time, as `BocView::cell` does. What it refuses is therefore
    // what the reader that builds everything refuses, and it has to refuse it the same way.
    let lazy = match LazyBoc::open(bytes) {
        Ok(lazy) => lazy,
        Err(refused) => {
            assert_eq!(
                materialized.as_ref().err(),
                Some(&refused),
                "the lazy reader refused a bag materialize did not"
            );
            return true;
        }
    };
    assert_eq!(
        lazy.cell_count(),
        view.cell_count(),
        "two readers counted a bag's cells differently"
    );
    assert_eq!(
        lazy.root_count(),
        view.root_count(),
        "two readers counted a bag's roots differently"
    );

    // A bag that materialized had every one of its cells built, so building one on its own
    // cannot fail. Bounded because the cost is per cell and a whole block is over a thousand.
    //
    // Taken from the deepest index down, which is children before parents, so each cell after
    // the first meets a subtree the reader is already holding. That is the state the reader
    // beside it never has: `BocView::cell` builds from nothing on every call, so the steps the
    // builder takes around ground already built are reached through this door and no other.
    if materialized.is_ok() {
        let reach = view.cell_count().min(CELLS_READ);
        let mut kept: Vec<Cell> = Vec::with_capacity(reach);
        for index in (0..reach).rev() {
            let Ok(alone) = view.cell(index) else {
                panic!("cell {index} of a bag that materialized would not build on its own");
            };
            let Ok(lazily) = lazy.cell(index) else {
                panic!("cell {index} of a bag that materialized would not build lazily");
            };
            assert_eq!(
                alone.repr_hash(),
                lazily.repr_hash(),
                "two readers gave cell {index} two identities"
            );
            kept.push(lazily);
        }

        // Asked a second time, in the other order, a cell has to come back as the cell the
        // reader is holding rather than as a second copy of it.
        for (index, cell) in kept.iter().rev().enumerate() {
            let Ok(again) = lazy.cell(index) else {
                panic!("cell {index} would not come back from the reader holding it");
            };
            assert!(
                cell.ptr_eq(&again),
                "cell {index} came back as a second copy of itself"
            );
        }
        // And the work says the same thing the handles do: a reader that never builds twice
        // has built exactly what it holds. A count of cells held cannot see a rebuild on its
        // own, because a rebuilt cell takes the slot of the one it replaced.
        assert_eq!(
            lazy.builds_run(),
            lazy.built_count(),
            "the reader ran {} builds to hold {} cells",
            lazy.builds_run(),
            lazy.built_count()
        );
    }

    // Last, because asking for a root builds everything under it, and a reader holding the
    // whole bag hands back what it holds without walking anything.
    if let Ok(built) = &materialized {
        let Ok(lazily) = lazy.roots() else {
            panic!("the roots of a bag that materialized would not build lazily");
        };
        assert_eq!(
            lazily.len(),
            built.len(),
            "two readers found different roots"
        );
        for (one, other) in lazily.iter().zip(built) {
            assert_eq!(
                one.repr_hash(),
                other.repr_hash(),
                "two readers gave one bag two identities"
            );
        }
    }
    true
}

/// The slice readers, driven by a script the input chooses.
///
/// A slice decodes integers, byte runs and references out of a cell a peer produced, and a
/// caller reading an unknown structure runs off the end of one all the time. What is checked
/// is that a read either moves the cursor forward inside the cell or fails having moved
/// nothing.
pub(super) fn slice_reads(bytes: &[u8]) -> bool {
    let Ok(roots) = parse_boc(bytes) else {
        return false;
    };
    let mut script = Rng::from_bytes(bytes);

    for cell in distinct_cells(&roots).iter().take(CELLS_READ) {
        let total_bits = usize::from(cell.bit_len());
        let total_refs = cell.refs().len();
        let mut slice = cell.parse();
        assert_eq!(
            slice.remaining_bits(),
            total_bits,
            "a fresh slice lost bits"
        );
        assert_eq!(
            slice.remaining_refs(),
            total_refs,
            "a fresh slice lost references"
        );

        // A whole cell copied back out is the same cell. An exotic one is not: a builder
        // makes ordinary cells, so the copy would be a different kind carrying the same
        // bytes and would rightly hash differently.
        if !cell.is_exotic() {
            if let Ok(copy) = slice.to_cell() {
                assert_eq!(
                    copy.repr_hash(),
                    cell.repr_hash(),
                    "a cell copied through a slice changed identity"
                );
            }
        }

        for _ in 0..READS_PER_CELL {
            let before_bits = slice.remaining_bits();
            let before_refs = slice.remaining_refs();
            let outcome = scripted_read(&mut slice, &mut script);
            let after_bits = slice.remaining_bits();
            let after_refs = slice.remaining_refs();

            assert!(
                after_bits <= before_bits,
                "a read gave bits back to the slice"
            );
            assert!(
                after_refs <= before_refs,
                "a read gave references back to the slice"
            );
            if outcome == Outcome::RefusedWhole {
                assert_eq!(
                    after_bits, before_bits,
                    "a read that failed as a whole spent bits"
                );
                assert_eq!(
                    after_refs, before_refs,
                    "a read that failed as a whole spent references"
                );
            }
        }
    }
    true
}

/// What a scripted read did to the cursor, as far as the caller can promise.
#[derive(PartialEq, Eq)]
enum Outcome {
    /// The read succeeded, or it failed partway through a value it had begun.
    Spent,
    /// The read failed and documents that nothing was consumed.
    RefusedWhole,
}

/// Performs one read the script chose, reporting what its failure would mean.
///
/// The split matters. A primitive read checks its whole width before it moves, so a failure
/// leaves the cursor exactly where it was. `load_maybe_ref` is two reads, a bit and then a
/// reference, and a bit once spent cannot be given back, so it can fail with its first half
/// consumed. Only the first group is held to the stronger rule.
///
/// The variable-length reads are two reads as well, a length and then that many bytes, and
/// they sit in the first group because they put the cursor back rather than leave it inside
/// a field they failed on.
fn scripted_read(slice: &mut Slice<'_>, script: &mut Rng) -> Outcome {
    let width = script.below(200);
    let refused_whole = match script.below(14) {
        0 => slice.load_bit().is_err(),
        1 => slice.load_uint(u32::try_from(width).unwrap_or(0)).is_err(),
        2 => slice
            .load_uint128(u32::try_from(width).unwrap_or(0))
            .is_err(),
        3 => slice.load_bytes(width).is_err(),
        4 => slice.skip_bits(width).is_err(),
        5 => slice.load_ref().is_err(),
        6 => slice.skip_refs(script.below(8)).is_err(),
        7 => slice.skip_bits_and_refs(width, script.below(8)).is_err(),
        8 => slice
            .load_slice(width, script.below(8))
            .map(|window| {
                assert!(
                    window.remaining_bits() <= width,
                    "a window reads more bits than it was cut to"
                );
            })
            .is_err(),
        9 => slice
            .load_bits(width)
            .map(|bits| {
                assert!(
                    bits.len() == width,
                    "a run of bits came back a different length than it was asked for"
                );
            })
            .is_err(),
        10 => slice
            .load_var_uint(u32::try_from(width % 33).unwrap_or(0))
            .is_err(),
        11 => slice
            .load_var_int(u32::try_from(width % 33).unwrap_or(0))
            .is_err(),
        12 => {
            // A subslice reads without advancing, so it is checked rather than counted.
            let taken = slice.subslice(script.below(64), width, script.below(4), script.below(4));
            if let Ok(window) = taken {
                assert!(
                    window.remaining_bits() <= slice.remaining_bits(),
                    "a window reaches past the slice it was cut from"
                );
                assert!(
                    window.remaining_refs() <= slice.remaining_refs(),
                    "a window holds references the slice it was cut from does not"
                );
            }
            return Outcome::RefusedWhole;
        }
        _ => {
            let _ = slice.load_maybe_ref();
            return Outcome::Spent;
        }
    };
    if refused_whole {
        Outcome::RefusedWhole
    } else {
        Outcome::Spent
    }
}

/// The dictionary readers, over a trie whose labels came off the wire.
///
/// A cell of the bag is opened as the root of each dictionary shape at a key width the input
/// chooses. What is checked is the key a walk hands back: its width is the dictionary's, and
/// the walk hands them over in ascending order, which is the property a label read wrongly or a
/// branch taken wrongly breaks first.
pub(super) fn dictionary(bytes: &[u8]) -> bool {
    let Ok(roots) = parse_boc(bytes) else {
        return false;
    };
    let mut script = Rng::from_bytes(bytes);

    for cell in distinct_cells(&roots).iter().take(CELLS_READ) {
        let key_bits = KEY_WIDTHS[script.below(KEY_WIDTHS.len())];
        let key_bytes = usize::from(key_bits).div_ceil(8);
        let key: Vec<u8> = (0..key_bytes).map(|_| script.byte()).collect();

        if let Ok(dict) = Dict::from_root(Some(cell.clone()), key_bits) {
            // A lookup descends one path, so its cost follows the key width rather than the
            // tree, and it needs no cap.
            let _ = dict.get(&key);
            walked_keys(dict.iter().map(|item| item.map(|(key, _)| key)), key_bytes);
        }

        if let Ok(dict) = AugDict::from_root(Sum, Some(cell.clone()), key_bits) {
            let _ = dict.get(&key);
            let _ = dict.root_extra();
            walked_keys(dict.iter().map(|item| item.map(|(key, _)| key)), key_bytes);
        }

        if let Ok(dict) = PfxDict::from_root(Some(cell.clone()), key_bits) {
            let _ = dict.get(&key, key_bits);
            let _ = dict.lookup_prefix(&key, key_bits);
            for item in dict.iter().take(WALK_CAP) {
                let Ok((prefix, prefix_bits, _)) = item else {
                    break;
                };
                assert!(
                    prefix_bits <= key_bits,
                    "a prefix dictionary of {key_bits} bit keys handed back a {prefix_bits} bit key"
                );
                assert_eq!(
                    prefix.len(),
                    usize::from(prefix_bits).div_ceil(8),
                    "a key's bytes do not follow from the bits it claims"
                );
            }
        }
    }
    true
}

/// Checks the keys a walk hands back, stopping at the cap the harness imposes.
///
/// The walk is capped because nothing in the crate caps it: see `WALK_CAP`. What is stopped
/// early is the walk, not the check, so every key that did come back is still held to its
/// width and its order.
fn walked_keys(walk: impl Iterator<Item = Result<Vec<u8>, CellError>>, key_bytes: usize) {
    let mut previous: Option<Vec<u8>> = None;
    for item in walk.take(WALK_CAP) {
        let Ok(key) = item else {
            break;
        };
        assert_eq!(
            key.len(),
            key_bytes,
            "a dictionary handed back a key of the wrong width"
        );
        if let Some(before) = &previous {
            assert!(
                before.as_slice() < key.as_slice(),
                "a dictionary walk went backwards or repeated a key"
            );
        }
        previous = Some(key);
    }
}

/// A summary that adds up, which is the shape of the augmentations TON itself uses.
///
/// The value is what a fork stores between its label and its branches, so reading one is a
/// decode of wire bytes in its own right, which is what this is here to reach.
struct Sum;

impl Augmentation for Sum {
    type Extra = u64;

    fn read(&self, slice: &mut Slice<'_>) -> Result<u64, CellError> {
        slice.load_uint(64)
    }

    fn combine(&self, left: &u64, right: &u64) -> Result<u64, CellError> {
        Ok(left.wrapping_add(*right))
    }

    fn write(&self, extra: &u64, into: &mut Builder) -> Result<(), CellError> {
        into.store_uint(*extra, 64)?;
        Ok(())
    }
}

/// The decompression boundary, where a small input names the size it expands to.
///
/// The cap on that size is what stands between a few bytes and a large allocation, so what
/// is checked is that the expansion stopped at the length the input named, that a length no
/// input could honestly carry is refused, and that the compressed door and the plain one
/// reach the same bag.
#[cfg(feature = "compress")]
pub(super) fn compressed(bytes: &[u8]) -> bool {
    use ton_net_cell::compress::{compress, decompress, decompress_boc};

    let mut expanded_any = false;
    if let Ok(expanded) = decompress(bytes) {
        expanded_any = true;
        let named = bytes
            .get(..4)
            .and_then(|prefix| <[u8; 4]>::try_from(prefix).ok())
            .map(u32::from_le_bytes)
            .and_then(|named| usize::try_from(named).ok());
        // The bound is `<=`, not `==`: the decoder sizes its buffer from the prefix and
        // truncates to what the body gave, so a short body comes back short. Nothing comes
        // back longer.
        assert!(
            named.is_some_and(|named| expanded.len() <= named),
            "decompression ran past the length the input named"
        );

        match (decompress_boc(bytes), parse_boc(&expanded)) {
            (Ok(one), Ok(other)) => {
                assert_eq!(one.len(), other.len(), "two readers found different roots");
                for (a, b) in one.iter().zip(&other) {
                    assert_eq!(
                        a.repr_hash(),
                        b.repr_hash(),
                        "two readers gave one bag two identities"
                    );
                }
            }
            (Err(one), Err(other)) => {
                assert_eq!(one, other, "two readers refused a bag differently");
            }
            _ => panic!("decompress_boc and parse_boc disagree on whether a bag reads"),
        }
    }

    // A prefix naming four gigabytes cannot be honest about any input this size, so it has
    // to be refused on the prefix rather than expanded towards.
    if bytes.len() >= 4 {
        let mut forged = bytes.to_vec();
        if let Some(prefix) = forged.get_mut(..4) {
            prefix.copy_from_slice(&u32::MAX.to_le_bytes());
        }
        assert!(
            decompress(&forged).is_err(),
            "a compressed bag naming four gigabytes was not refused"
        );
    }

    assert_eq!(
        decompress(&compress(bytes)).expect("what compress wrote decompresses"),
        bytes,
        "compression did not round trip"
    );
    expanded_any
}
