// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Nirapod Labs

//! Fuzzing the decode boundary, where bytes a peer chose become values this client trusts.
//!
//! Everything below `parse_boc` reads a length, a count or an index that an attacker wrote.
//! That is why the crate root forbids unsafe code and denies the panicking helpers. A lint
//! rules out one way of failing; a fuzzer looks for the rest, and it looks over inputs
//! nobody sat down and wrote.
//!
//! # The mechanism, and why this one
//!
//! `cargo-fuzz` drives libFuzzer, which needs a nightly toolchain for its sanitizer flags.
//! `rust-toolchain.toml` pins stable, and every Rust job in `.github/workflows/ci.yml`
//! names `stable`, `1.85.0` or `1.88.0`, so a nightly-only target here would be a target
//! nothing in this repository runs. That is worse than no target: it reads as coverage and
//! provides none.
//!
//! What runs on stable is this. Each target is a plain `fn(&[u8])` over one hostile byte
//! string, and a deterministic loop generates those byte strings from a corpus of captured
//! mainnet bags. The signature is the one every coverage-guided driver consumes, so if a
//! nightly or an AFL job is ever added, the targets are reused rather than rewritten. It
//! adds no dependency, which matters because `deny.toml` refuses a second copy of anything
//! already in the tree and vets each license and advisory, so a crate is a decision here
//! rather than a line in a manifest (NET-ADR-004).
//!
//! # What the targets assert
//!
//! Not that the process survived, which the test runner gives away. Each target holds the
//! reader to the properties that make the boundary sound:
//!
//! - What parses stays inside the limits the crate publishes: `MAX_CELLS`, `MAX_DEPTH`,
//!   `MAX_BITS` and `MAX_REFS`, and a cell's stored bytes are the ones its bit count needs.
//! - What parses is bounded by its own input. A bag reaches at most one cell per two bytes
//!   it carries, because the header reader refuses a count the remaining bytes could not
//!   hold before it allocates for that count.
//! - The doors agree. `parse_boc`, `BocView::materialize`, `BocView::verify` and
//!   `BocView::cell` read the same bag through four paths, and every input has to reach the
//!   same answer or the same error down all four.
//! - What parses round trips. Serializing a parsed bag and reading it back gives the same
//!   root representation hashes, and serializing again gives the same bytes.
//!
//! # Where this sits beside what was already here
//!
//! `src/proptests.rs` generates cell trees and goes out through the serializer, so every
//! encoding it sees is one this crate wrote. `tests/cell/hostile.rs` mutates one captured
//! proof and asserts that nothing panics. This adds the parts neither reaches: the whole
//! fixture set rather than one file, header shapes written field by field rather than
//! edited a byte at a time, a checksum repaired after a mutation so the edit reaches a cell
//! instead of stopping at the checksum gate, read scripts driven by the input itself, and
//! the limit, agreement and boundedness assertions above in place of a bare no-panic check.
//!
//! # Running it
//!
//! `cargo test -p ton-net-cell fuzz` runs the gate budget. `TON_NET_FUZZ_ITERATIONS` and
//! `TON_NET_FUZZ_SEED` set how long and from where; `docs/fuzzing.md` covers both and says
//! what to do with a failure.

mod targets;

use std::collections::HashSet;
use std::fmt::Write as _;

use ton_net_cell::{parse_boc, serialize_boc_with, BocOptions, Builder, Cell};

use crate::whole_block::unhex;

/// The captured mainnet bags every case is built from.
///
/// Random bytes stop at the magic number, and bytes that get past it stop at the first
/// count, so a corpus of real bags is what reaches the reference decoding, the exotic
/// classification and the stored-hash check at all. The account proof carries exotic cells;
/// the two blocks carry stored hashes and complete dictionaries.
const ACCOUNT_PROOF: &str = include_str!("../fixtures/account-proof.hex");
const BLOCK_MASTERCHAIN: &str = include_str!("../fixtures/block-masterchain.hex");
const BLOCK_BASECHAIN: &str = include_str!("../fixtures/block-basechain.hex");

/// The four bytes every bag of cells begins with.
const MAGIC: [u8; 4] = [0xb5, 0xee, 0x9c, 0x72];

/// One cell of eight bits holding `0xab`, the smallest bag that parses.
const ONE_CELL: [u8; 14] = [
    0xb5, 0xee, 0x9c, 0x72, 0x01, 0x01, 0x01, 0x01, 0x00, 0x03, 0x00, 0x00, 0x02, 0xab,
];

/// A root with one reference, the smallest bag that exercises the reference decoding.
const TWO_CELLS: [u8; 17] = [
    0xb5, 0xee, 0x9c, 0x72, 0x01, 0x01, 0x02, 0x01, 0x00, 0x06, 0x00, 0x01, 0x00, 0x01, 0x00, 0x02,
    0xcd,
];

/// Byte values a decoder tends to split on: an empty byte, a low bit, both sides of the
/// signed boundary, and a full one.
const INTERESTING: [u8; 8] = [0x00, 0x01, 0x02, 0x7f, 0x80, 0x81, 0xfe, 0xff];

/// The environment variable naming how many cases each target runs.
const ITERATIONS_VAR: &str = "TON_NET_FUZZ_ITERATIONS";

/// The environment variable naming the seed the cases are generated from.
const SEED_VAR: &str = "TON_NET_FUZZ_SEED";

/// Cases per target when the environment names no other number.
///
/// Small, because this runs in the gate on every push and the gate is what a contributor
/// waits on. A long run sets `TON_NET_FUZZ_ITERATIONS` instead, which is what the scheduled
/// job in `.github/workflows/ci.yml` does.
const GATE_ITERATIONS: usize = 1_500;

/// The seed the cases are generated from when the environment names no other.
///
/// Fixed, so a failure in the gate reproduces from the same two numbers the run printed
/// rather than from whatever the clock said.
const DEFAULT_SEED: u64 = 0x5346_5546_465A_5A55;

/// The fraction of a run's cases that has to get past the reader, as a divisor.
///
/// Measured runs sit far above this; it is a floor under a harness that has stopped
/// working, not a target to reach.
const REACH_DIVISOR: usize = 20;

/// How many levels the shared-subtree dictionary seed carries.
///
/// Each level doubles the entries a walk over it visits, so this is the largest value that
/// stays cheap. `docs/fuzzing.md` records what the shape is for and what it showed.
const SHARED_LEVELS: usize = 12;

/// A deterministic stream of fuzz decisions.
///
/// `splitmix64`, which is a few lines and passes the statistical tests a mutation schedule
/// needs. The point is reproducibility rather than randomness: a case is a function of the
/// seed and its index, so a failure is re-run rather than hunted for again.
pub struct Rng(u64);

impl Rng {
    /// A stream from an explicit seed.
    pub fn new(seed: u64) -> Self {
        Self(seed)
    }

    /// A stream seeded from a case's own bytes.
    ///
    /// The targets that drive a read script need choices beyond the bag itself: which read
    /// to make, how wide, which key width to open a dictionary at. Taking those from the
    /// input rather than from the driver keeps every target a function of one byte string,
    /// which is what lets a mutation explore the script as well as the bag, and what keeps
    /// the `fn(&[u8])` shape a coverage-guided driver expects.
    pub fn from_bytes(bytes: &[u8]) -> Self {
        let mut state: u64 = 0xcbf2_9ce4_8422_2325;
        for &byte in bytes {
            state = (state ^ u64::from(byte)).wrapping_mul(0x0000_0100_0000_01b3);
        }
        Self(state)
    }

    /// The next value in the stream.
    pub fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        z ^ (z >> 31)
    }

    /// A value under `bound`, or zero when there is no such value.
    pub fn below(&mut self, bound: usize) -> usize {
        if bound == 0 {
            return 0;
        }
        let bound = u64::try_from(bound).unwrap_or(u64::MAX);
        usize::try_from(self.next() % bound).unwrap_or(0)
    }

    /// The next byte of the stream.
    pub fn byte(&mut self) -> u8 {
        u8::try_from(self.next() & 0xff).unwrap_or(0)
    }
}

/// The CRC-32C of `bytes`, reflected form, which is the checksum a bag of cells trails
/// itself with.
///
/// Written here rather than borrowed from the crate because the crate keeps it private, and
/// because of what it is for: a mutation inside a checksummed bag is refused at the
/// checksum and never reaches a cell, so the driver has to be able to make the bytes
/// consistent again before an edit is worth running.
fn crc32c(bytes: &[u8]) -> u32 {
    let mut crc = 0xffff_ffffu32;
    for &byte in bytes {
        crc ^= u32::from(byte);
        for _ in 0..8 {
            crc = if crc & 1 == 0 {
                crc >> 1
            } else {
                (crc >> 1) ^ 0x82f6_3b78
            };
        }
    }
    !crc
}

/// Rewrites the trailing checksum of a bag whose flags say it carries one.
fn repair_checksum(bytes: &mut [u8]) {
    if bytes.len() < 12 || bytes.get(..4) != Some(&MAGIC[..]) {
        return;
    }
    let carries_checksum = bytes.get(4).is_some_and(|flags| flags & 0x40 != 0);
    if !carries_checksum {
        return;
    }
    let split = bytes.len() - 4;
    let (body, tail) = bytes.split_at_mut(split);
    tail.copy_from_slice(&crc32c(body).to_le_bytes());
}

/// Appends `value` to `out` as `width` big-endian bytes.
fn push_be(out: &mut Vec<u8>, value: u64, width: usize) {
    for shift in (0..width.min(8)).rev() {
        out.push(u8::try_from((value >> (shift * 8)) & 0xff).unwrap_or(0));
    }
}

/// Writes `value` over the `width` bytes at `at` as a big-endian field.
fn write_be(bytes: &mut [u8], at: usize, value: usize, width: usize) {
    for offset in 0..width.min(8) {
        let shift = (width.min(8) - 1 - offset) * 8;
        if let Some(slot) = bytes.get_mut(at + offset) {
            *slot = u8::try_from((value >> shift) & 0xff).unwrap_or(0);
        }
    }
}

/// Reads `width` big-endian bytes at `at`.
fn read_be(bytes: &[u8], at: usize, width: usize) -> Option<usize> {
    let field = bytes.get(at..at.checked_add(width)?)?;
    field.iter().try_fold(0usize, |value, &byte| {
        value.checked_mul(256)?.checked_add(usize::from(byte))
    })
}

/// Rewrites a bag's stated cell-area size to the number of bytes that follow the header.
///
/// The header reader holds a bag to its own account of how many bytes its cells take, and
/// refuses one whose account and length disagree. That check runs before any cell is read,
/// so an edit that changes a bag's length is refused at the accounting and the bytes it
/// changed are never looked at. Restoring the account is what puts an inserted, removed or
/// truncated byte in front of the cell reader, which is where the interesting failures are.
fn repair_cell_area(bytes: &mut [u8]) {
    if bytes.get(..4) != Some(&MAGIC[..]) {
        return;
    }
    let Some(&flags) = bytes.get(4) else {
        return;
    };
    let Some(&offset_size) = bytes.get(5) else {
        return;
    };
    let ref_size = usize::from(flags & 0x07);
    let offset_size = usize::from(offset_size);
    if !(1..=4).contains(&ref_size) || !(1..=8).contains(&offset_size) {
        return;
    }

    let Some(count) = read_be(bytes, 6, ref_size) else {
        return;
    };
    let Some(roots) = read_be(bytes, 6 + ref_size, ref_size) else {
        return;
    };
    let area_field = 6 + 3 * ref_size;

    // Everything the header spends before the cells: its own fields, the root list, and the
    // offset index when the flags say one is there.
    let mut header_len = area_field + offset_size + roots * ref_size;
    if flags & 0x80 != 0 {
        header_len += count * offset_size;
    }
    let body_end = if flags & 0x40 != 0 {
        bytes.len().checked_sub(4)
    } else {
        Some(bytes.len())
    };
    let Some(cell_area) = body_end.and_then(|end| end.checked_sub(header_len)) else {
        return;
    };
    write_be(bytes, area_field, cell_area, offset_size);
}

/// The bags every case starts from.
///
/// The captured fixtures are the ground truth, and the rest of the list covers the header
/// shapes a capture may not happen to carry: the offset index and the trailing checksum are
/// written here in all four combinations so both are reached whatever the fixtures hold.
fn corpus() -> Vec<Vec<u8>> {
    let mut seeds = vec![
        unhex(ACCOUNT_PROOF),
        unhex(BLOCK_MASTERCHAIN),
        unhex(BLOCK_BASECHAIN),
        ONE_CELL.to_vec(),
        TWO_CELLS.to_vec(),
        shared_subtree_dictionary(SHARED_LEVELS),
    ];

    if let Ok(roots) = parse_boc(&unhex(ACCOUNT_PROOF)) {
        for index in [false, true] {
            for crc32c in [false, true] {
                if let Ok(bag) = serialize_boc_with(&roots, &BocOptions { index, crc32c }) {
                    seeds.push(bag);
                }
            }
        }
    }
    seeds
}

/// A bag whose cells form a chain of dictionary forks, each pointing at the next cell twice.
///
/// Every cell of the chain is a fork with an empty label and two references, and both
/// references name the same next cell, which is a shape the format allows: a reference has
/// to point strictly forward and this one does. The bag is `levels + 1` cells, and the
/// dictionary it roots holds two entries for every entry the level below it holds.
///
/// It is in the corpus because a decode boundary is a place where the cost of reading has
/// to follow the size of the input, and this is the shape where it does not.
/// `docs/fuzzing.md` records what a walk over it costs.
fn shared_subtree_dictionary(levels: usize) -> Vec<u8> {
    let mut cells: Vec<u8> = Vec::new();
    for index in 0..levels {
        // Two references, ordinary, and two bits of data: a `hml_short` label of length
        // zero, then the completion tag the stored form carries.
        cells.extend_from_slice(&[0x02, 0x01, 0x20]);
        let next = u8::try_from(index + 1).unwrap_or(u8::MAX);
        cells.push(next);
        cells.push(next);
    }
    // The leaf, with no references and the same empty label.
    cells.extend_from_slice(&[0x00, 0x01, 0x20]);

    let mut bag = Vec::from(MAGIC);
    bag.push(0x01); // one byte per reference index, no index, no checksum
    bag.push(0x02); // two bytes per offset
    push_be(&mut bag, u64::try_from(levels + 1).unwrap_or(0), 1);
    push_be(&mut bag, 1, 1); // one root
    push_be(&mut bag, 0, 1); // no absent cells
    push_be(&mut bag, u64::try_from(cells.len()).unwrap_or(0), 2);
    push_be(&mut bag, 0, 1); // the root is cell zero
    bag.extend_from_slice(&cells);
    bag
}

/// The compressed forms of those bags, which is a different encoding and its own corpus.
///
/// A bag of cells handed to `decompress` is refused on its first four bytes, read as a
/// length prefix, and never reaches the decoder: over the bag corpus above, two cases in
/// fifteen hundred got past that. The compressed corpus is the same bags compressed, so an
/// edit lands inside a real LZ4 stream where a token, a match offset or a literal run is
/// what changes.
#[cfg(feature = "compress")]
fn compressed_corpus() -> Vec<Vec<u8>> {
    let mut seeds: Vec<Vec<u8>> = corpus()
        .iter()
        .map(|bag| ton_net_cell::compress::compress(bag))
        .collect();
    // A prefix with nothing behind it, and one naming more than the cap allows: the two
    // shapes the checks in front of the decoder are written for.
    seeds.push(0u32.to_le_bytes().to_vec());
    seeds.push(u32::MAX.to_le_bytes().to_vec());
    seeds
}

/// Builds one compressed case.
///
/// The length prefix is the field the cap is applied to, so it is chosen outright as often
/// as it is edited: an edit moves it by one bit, and what decides the allocation is its
/// whole value.
#[cfg(feature = "compress")]
fn compressed_case(rng: &mut Rng, corpus: &[Vec<u8>]) -> Vec<u8> {
    match rng.below(8) {
        0 => (0..rng.below(64)).map(|_| rng.byte()).collect(),
        1 => {
            let named = u32::try_from(rng.below(1 << 28)).unwrap_or(0);
            let mut out = named.to_le_bytes().to_vec();
            let pick = rng.below(corpus.len());
            let body = corpus.get(pick).cloned().unwrap_or_default();
            out.extend(body.get(4..).unwrap_or_default());
            out
        }
        _ => edited(rng, corpus),
    }
}

/// Builds one bag-of-cells case: bytes with a seed behind them, or bytes with none.
fn boc_case(rng: &mut Rng, corpus: &[Vec<u8>]) -> Vec<u8> {
    let mut bytes = match rng.below(16) {
        0 => (0..rng.below(128)).map(|_| rng.byte()).collect(),
        1 => {
            // Arbitrary bytes stop at the magic number, so a prefixed run is what puts
            // chosen values where the counts and the cell descriptors are read.
            let mut out = Vec::from(MAGIC);
            out.extend((0..rng.below(96)).map(|_| rng.byte()));
            out
        }
        2 | 3 => header_shaped(rng, corpus),
        4..=9 => derived(rng, corpus),
        _ => edited(rng, corpus),
    };
    // A bag states its own length and carries its own checksum, and an edit breaks both
    // before it reaches a cell. Each is repaired most of the time and left broken the rest,
    // which keeps the cells under test without taking the two gates in front of them out of
    // it.
    if rng.below(4) != 0 {
        repair_cell_area(&mut bytes);
    }
    if rng.below(4) != 0 {
        repair_checksum(&mut bytes);
    }
    bytes
}

/// Every distinct cell a bag's roots reach.
///
/// A bag stores a cell shared by two parents once, so a walk that does not remember what it
/// has seen repeats that subtree once per path to it. Keying on the representation hash is
/// what keeps this walk proportional to the bag: two cells with one hash would be a SHA-256
/// collision, so the hash identifies the cell.
pub fn distinct_cells(roots: &[Cell]) -> Vec<Cell> {
    let mut seen: HashSet<[u8; 32]> = HashSet::new();
    let mut out = Vec::new();
    let mut stack: Vec<Cell> = roots.to_vec();
    while let Some(cell) = stack.pop() {
        if !seen.insert(*cell.repr_hash()) {
            continue;
        }
        stack.extend(cell.refs().iter().cloned());
        out.push(cell);
    }
    out
}

/// A bag built from part of a real one: a subtree lifted out, sometimes with a cell changed.
///
/// A byte edit inside a captured bag lands on a cell descriptor about as often as on cell
/// data, and a changed descriptor moves every cell after it, so the bag stops reading at the
/// first one and the edit is never read as a cell. Measured over this corpus, byte editing
/// alone got about three cases in a hundred past `parse_boc`.
///
/// Going through the cell model instead keeps the bag readable. A subtree of a mainnet block
/// serialized on its own is a valid bag whose root is a dictionary node, a pruned branch or
/// a Merkle proof, which is what puts the readers above the parser in front of real
/// structure rather than in front of a refusal. The byte edit that follows then lands on a
/// bag small enough that it is read rather than lost.
fn derived(rng: &mut Rng, corpus: &[Vec<u8>]) -> Vec<u8> {
    let pick = rng.below(corpus.len());
    let seed = corpus.get(pick).cloned().unwrap_or_default();
    let Ok(roots) = parse_boc(&seed) else {
        return seed;
    };

    let cells = distinct_cells(&roots);
    let Some(cell) = cells.get(rng.below(cells.len())).cloned() else {
        return seed;
    };
    let root = if rng.below(2) == 0 {
        cell
    } else {
        changed(rng, &cell)
    };

    let options = BocOptions {
        index: rng.below(2) == 0,
        crc32c: rng.below(2) == 0,
    };
    let mut bag = serialize_boc_with(&[root], &options).unwrap_or(seed);
    if rng.below(3) == 0 && !bag.is_empty() {
        let at = rng.below(bag.len());
        bag[at] ^= 1 << rng.below(8);
    }
    bag
}

/// The same cell with some of its data bits flipped.
///
/// An exotic cell comes back untouched: its meaning is fixed by the hashes it carries, a
/// builder makes ordinary cells, and a copy that changed kind would be a different cell
/// rather than a changed one.
fn changed(rng: &mut Rng, cell: &Cell) -> Cell {
    if cell.is_exotic() {
        return cell.clone();
    }
    let total = usize::from(cell.bit_len());
    let flips: Vec<usize> = (0..rng.below(8)).map(|_| rng.below(total.max(1))).collect();

    let mut builder = Builder::new();
    let mut bits = cell.parse();
    for index in 0..total {
        let Ok(bit) = bits.load_bit() else {
            return cell.clone();
        };
        let bit = if flips.contains(&index) { !bit } else { bit };
        if builder.store_bit(bit).is_err() {
            return cell.clone();
        }
    }
    for child in cell.refs() {
        if builder.store_ref(child.clone()).is_err() {
            return cell.clone();
        }
    }
    builder.build().unwrap_or_else(|_| cell.clone())
}

/// A corpus seed put through the byte-level edits a peer could make.
fn edited(rng: &mut Rng, corpus: &[Vec<u8>]) -> Vec<u8> {
    let pick = rng.below(corpus.len());
    let mut bytes = corpus.get(pick).cloned().unwrap_or_default();
    for _ in 0..=rng.below(8) {
        if bytes.is_empty() {
            break;
        }
        let at = rng.below(bytes.len());
        match rng.below(7) {
            0 => bytes[at] ^= 1 << rng.below(8),
            1 => bytes[at] = INTERESTING[rng.below(INTERESTING.len())],
            2 => bytes[at] = rng.byte(),
            3 => bytes.truncate(at),
            4 => bytes.insert(at, rng.byte()),
            5 => {
                bytes.remove(at);
            }
            _ => {
                // A run lifted out of another seed. A length field is the field worth
                // moving whole: a count that came from a real bag is plausible enough to
                // be read rather than refused at the first range check.
                let other = corpus
                    .get(rng.below(corpus.len()))
                    .cloned()
                    .unwrap_or_default();
                if other.is_empty() {
                    continue;
                }
                let from = rng.below(other.len());
                let len = rng.below((other.len() - from).min(bytes.len() - at) + 1);
                for offset in 0..len {
                    if let (Some(target), Some(source)) =
                        (bytes.get_mut(at + offset), other.get(from + offset))
                    {
                        *target = *source;
                    }
                }
            }
        }
    }
    bytes
}

/// A header built field by field, over a cell area taken from a seed.
///
/// Editing a captured bag reaches the header one byte at a time, and a header field is
/// where a single byte is most often refused at the first range check. Writing the fields
/// directly puts a chosen reference size, offset size, cell count, root count and
/// cell-area size in front of real cell bytes, which is where the accounting between those
/// five is decided rather than where each one is range-checked.
fn header_shaped(rng: &mut Rng, corpus: &[Vec<u8>]) -> Vec<u8> {
    // Deliberately wider than the reader accepts at each end, so the range checks are
    // exercised alongside the accounting.
    let ref_size = rng.below(8);
    let offset_size = rng.below(10);
    let has_index = rng.below(4) == 0;
    let has_checksum = rng.below(2) == 0;

    let pick = rng.below(corpus.len());
    let seed = corpus.get(pick).cloned().unwrap_or_default();
    let from = rng.below(seed.len().max(1));
    let area: Vec<u8> = seed.get(from..).unwrap_or_default().to_vec();

    let count = match rng.below(4) {
        0 => rng.below(1 << 20),
        1 => area.len() / 2,
        2 => usize::MAX,
        _ => rng.below(8),
    };
    let roots = if rng.below(4) == 0 {
        rng.below(1 << 16)
    } else {
        1 + rng.below(3)
    };
    let cell_area = if rng.below(4) == 0 {
        rng.below(1 << 24)
    } else {
        area.len()
    };

    let mut bag = Vec::from(MAGIC);
    let mut flags = u8::try_from(ref_size & 0x07).unwrap_or(0);
    if has_index {
        flags |= 0x80;
    }
    if has_checksum {
        flags |= 0x40;
    }
    bag.push(flags);
    bag.push(u8::try_from(offset_size).unwrap_or(0));
    push_be(&mut bag, u64::try_from(count).unwrap_or(u64::MAX), ref_size);
    push_be(&mut bag, u64::try_from(roots).unwrap_or(u64::MAX), ref_size);
    push_be(&mut bag, 0, ref_size);
    push_be(
        &mut bag,
        u64::try_from(cell_area).unwrap_or(u64::MAX),
        offset_size,
    );
    for _ in 0..roots.min(64) {
        push_be(
            &mut bag,
            u64::try_from(rng.below(count.max(1))).unwrap_or(0),
            ref_size,
        );
    }
    bag.extend_from_slice(&area);
    if has_checksum {
        bag.extend_from_slice(&[0, 0, 0, 0]);
    }
    bag
}

/// How many cases a target runs.
fn iterations() -> usize {
    let Ok(text) = std::env::var(ITERATIONS_VAR) else {
        return GATE_ITERATIONS;
    };
    text.trim().parse().unwrap_or(GATE_ITERATIONS)
}

/// The seed the cases are generated from.
fn seed() -> u64 {
    let Ok(text) = std::env::var(SEED_VAR) else {
        return DEFAULT_SEED;
    };
    let text = text.trim();
    let parsed = match text.strip_prefix("0x") {
        Some(hex) => u64::from_str_radix(hex, 16),
        None => text.parse(),
    };
    parsed.unwrap_or(DEFAULT_SEED)
}

/// Names the bytes a case ran on when that case is unwinding.
///
/// A failing assertion says what broke. Without this it does not say what broke it, and a
/// driver that generated the input inside a loop cannot be asked afterwards.
struct Case<'a> {
    target: &'static str,
    seed: u64,
    index: usize,
    input: &'a [u8],
}

impl Drop for Case<'_> {
    fn drop(&mut self) {
        if !std::thread::panicking() {
            return;
        }
        let mut hex = String::with_capacity(self.input.len() * 2);
        for byte in self.input {
            let _ = write!(hex, "{byte:02x}");
        }
        eprintln!(
            "fuzz target {} failed on case {} of seed {:#018x}, {} bytes:\n{hex}",
            self.target,
            self.index,
            self.seed,
            self.input.len(),
        );
    }
}

/// Runs `target` over generated cases for the budget the environment allows.
///
/// The stream is seeded from the run's seed and the target's name together, so two targets
/// of one run see different inputs while each still reproduces on its own.
///
/// A target answers whether the reader accepted the case, which is the one thing a run of
/// this shape cannot see for itself. Without it a corpus that stopped reaching the reader,
/// a fixture that moved or a repair that stopped repairing would leave every target green
/// while checking nothing past the first refusal, so the run is held to a floor on what it
/// got through. The floor is deliberately far under what a working corpus reaches, since it
/// is there to catch a harness that has stopped working rather than to measure one that has
/// not.
fn run(
    name: &'static str,
    target: fn(&[u8]) -> bool,
    corpus: &[Vec<u8>],
    case: fn(&mut Rng, &[Vec<u8>]) -> Vec<u8>,
) {
    let seed = seed();
    let stream = seed ^ Rng::from_bytes(name.as_bytes()).next();
    let mut rng = Rng::new(stream);
    let iterations = iterations();
    let mut accepted = 0usize;

    for index in 0..iterations {
        let input = case(&mut rng, corpus);
        let guard = Case {
            target: name,
            seed,
            index,
            input: &input,
        };
        if target(&input) {
            accepted += 1;
        }
        drop(guard);
    }

    // Visible under `--nocapture`, which is how a long run reports what it covered rather than
    // only that it finished.
    eprintln!(
        "fuzz target {name}: {accepted} of {iterations} cases past the reader, seed {seed:#018x}"
    );
    let floor = iterations / REACH_DIVISOR;
    assert!(
        accepted >= floor,
        "fuzz target {name} got {accepted} of {iterations} cases past the reader, under the \
         floor of {floor}: the corpus or the repairs in front of it have stopped working"
    );
}

#[test]
fn a_bag_that_parses_stays_inside_the_limits_it_was_read_under() {
    run("bag_of_cells", targets::bag_of_cells, &corpus(), boc_case);
}

#[test]
fn every_door_onto_a_bag_reaches_the_same_answer() {
    run("header", targets::header, &corpus(), boc_case);
}

#[test]
fn a_slice_reads_only_what_the_cell_it_opened_holds() {
    run("slice_reads", targets::slice_reads, &corpus(), boc_case);
}

#[test]
fn a_dictionary_read_off_the_wire_yields_ordered_keys_of_its_own_width() {
    run("dictionary", targets::dictionary, &corpus(), boc_case);
}

#[cfg(feature = "compress")]
#[test]
fn a_compressed_bag_expands_only_to_the_length_it_names() {
    run(
        "compressed",
        targets::compressed,
        &compressed_corpus(),
        compressed_case,
    );
}
