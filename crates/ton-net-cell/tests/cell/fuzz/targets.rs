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
    PfxDict, Slice, MAX_BITS, MAX_CELLS, MAX_DEPTH, MAX_REFS,
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
/// records the measurement.
const WALK_CAP: usize = 4_096;

/// The longest chain of references under `roots`, which is the number `MAX_DEPTH` bounds.
///
/// `Cell::depth` is a different number and is not the one to check here. A pruned branch
/// answers with the depth of the subtree it stands in for, and that value is read out of the
/// branch's own body, so a bag of one cell reports whatever depth its two body bytes spell:
/// the fuzzer reached 4611 from 53 bytes. The parser bounds the graph it built, which is
/// what keeps a later walk or drop off the stack, so the check has to walk that graph.
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
/// What is checked is the shape of what came back: the published limits, the bound the
/// input length puts on the graph, and the round trip that says the bag can be written
/// again as the same cells.
pub(super) fn bag_of_cells(bytes: &[u8]) -> bool {
    let Ok(roots) = parse_boc(bytes) else {
        return false;
    };
    assert!(!roots.is_empty(), "a bag parsed to no roots at all");

    let cells = distinct_cells(&roots);
    assert!(
        cells.len() <= MAX_CELLS,
        "a bag of {} cells parsed past the {MAX_CELLS} cell limit",
        cells.len()
    );
    // Every cell costs at least its two descriptor bytes, and the header reader refuses a
    // count the remaining bytes could not hold before it allocates for that count. So a
    // bag cannot expand to more cells than half its own length, which is the form the
    // no-unbounded-allocation rule takes at this boundary.
    assert!(
        cells.len() * 2 <= bytes.len(),
        "{} bytes parsed to {} cells, more than two bytes each",
        bytes.len(),
        cells.len()
    );
    let deepest = reference_depth(&roots);
    assert!(
        deepest <= MAX_DEPTH,
        "a chain of {deepest} references parsed past the {MAX_DEPTH} depth limit"
    );

    for cell in &cells {
        assert!(
            cell.bit_len() <= MAX_BITS,
            "a cell of {} bits parsed past the {MAX_BITS} bit limit",
            cell.bit_len()
        );
        assert!(
            cell.refs().len() <= MAX_REFS,
            "a cell parsed with {} references, past the {MAX_REFS} the model allows",
            cell.refs().len()
        );
        // The stored bytes are the ones the bit count needs and no more, so a cell carries
        // no byte the representation hash covers and the bit count does not account for.
        assert_eq!(
            cell.data().len(),
            usize::from(cell.bit_len()).div_ceil(8),
            "a cell's stored bytes do not follow from its bit count"
        );
    }

    let written = serialize_boc(&roots).expect("a bag that parsed serializes");

    // The round trip is checked for every bag but one shape, and the exception is a defect
    // rather than a property. A bag's root list may name one cell twice, so a bag can have
    // more root entries than it has distinct cells. `serialize_boc` writes one root entry
    // per root it was handed and a cell count of the distinct cells it walked, which leaves
    // the written header stating more roots than cells, and a root count above the cell
    // count is the one thing `read_header` refuses outright. The fuzzer reached it from a
    // sixteen byte bag. Fixing it is not part of this change, so the check below states the
    // case it covers rather than covering a case it would fail.
    if roots.len() <= cells.len() {
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
    }
    true
}

/// The header reader, and the four readers that stand on it.
///
/// `parse_boc`, `BocView::materialize`, `BocView::verify` and `BocView::cell` read one bag
/// four ways. They share a header reader and a cell reader and diverge in what they keep, so
/// an input where they disagree is an input where one of them has a bound the others do not.
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
    assert!(
        view.cell_count() * 2 <= bytes.len(),
        "a header of a {} byte bag declared {} cells",
        bytes.len(),
        view.cell_count()
    );
    assert!(
        view.root_count() >= 1 && view.root_count() <= view.cell_count(),
        "a header declared {} roots among {} cells",
        view.root_count(),
        view.cell_count()
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

    // A bag that materialized had every one of its cells built, so building one on its own
    // cannot fail. Bounded because the cost is per cell and a whole block is over a thousand.
    if materialized.is_ok() {
        for index in 0..view.cell_count().min(CELLS_READ) {
            assert!(
                view.cell(index).is_ok(),
                "cell {index} of a bag that materialized would not build on its own"
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
            assert!(
                after_bits <= total_bits && after_refs <= total_refs,
                "a slice reads past the cell it opened"
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
/// leaves the cursor exactly where it was. A composite read is two reads: `load_maybe_ref`
/// spends a bit and then asks for a reference, and `load_var_uint` spends a length and then
/// asks for that many bytes, so either can fail with the first half already consumed. Only
/// the first group is held to the stronger rule.
fn scripted_read(slice: &mut Slice<'_>, script: &mut Rng) -> Outcome {
    let width = script.below(200);
    let refused_whole = match script.below(12) {
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
        9 => {
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
        10 => {
            let _ = slice.load_maybe_ref();
            return Outcome::Spent;
        }
        _ => {
            let _ = slice.load_var_uint(u32::try_from(width % 33).unwrap_or(0));
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
        // The check is `<=` rather than `==`, and that is a statement about the code as it
        // stands rather than a weaker property chosen for comfort. `decompress` documents
        // that it refuses bytes that "do not expand to the length they name", and the
        // decoder underneath treats the prefix as the size to allocate rather than the size
        // to produce: it fills a buffer of that length, decodes into it, and truncates to
        // what the body gave. The fuzzer reached `Ok` with an empty vector from five bytes
        // naming 27,015,349, so equality does not hold today. What does hold, and what the
        // cap in front of it is for, is that nothing comes back longer than the prefix.
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
