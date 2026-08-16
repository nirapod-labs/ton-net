// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Nirapod Labs

//! What the cell layer costs, over bytes captured from mainnet.
//!
//! A sync parses and hashes a bag of cells per link, over a thousand of them on a first
//! walk, so this is the floor under the whole client. Parsing includes hashing: a cell's
//! representation hash is computed as the tree is built, because a cell that has not been
//! hashed cannot be checked against anything.
//!
//! The inputs are the committed fixtures, so this runs offline and measures the same
//! bytes every time.

use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use ton_net::cell::{parse_boc, serialize_boc};

/// A real account proof, the size a single read carries.
const PROOF_HEX: &str = include_str!("../tests/fixtures/account-proof.hex");

fn decode(hex: &str) -> Vec<u8> {
    let trimmed: String = hex.chars().filter(|c| !c.is_whitespace()).collect();
    (0..trimmed.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&trimmed[i..i + 2], 16).expect("the fixture is hex"))
        .collect()
}

fn cells(c: &mut Criterion) {
    let proof = decode(PROOF_HEX);

    let mut group = c.benchmark_group("boc");
    group.throughput(Throughput::Bytes(proof.len() as u64));

    // Parse and hash. This is the cost a proof check pays before it checks anything.
    group.bench_with_input(
        BenchmarkId::new("parse", proof.len()),
        &proof,
        |b, bytes| b.iter(|| parse_boc(std::hint::black_box(bytes)).expect("the fixture parses")),
    );

    let roots = parse_boc(&proof).expect("the fixture parses");
    group.bench_with_input(
        BenchmarkId::new("serialize", proof.len()),
        &roots,
        |b, roots| {
            b.iter(|| {
                serialize_boc(std::hint::black_box(roots)).expect("a parsed tree serializes")
            });
        },
    );

    // The round trip, which is what a proof that gets rebuilt costs end to end.
    group.bench_with_input(
        BenchmarkId::new("round trip", proof.len()),
        &proof,
        |b, bytes| {
            b.iter(|| {
                let roots = parse_boc(std::hint::black_box(bytes)).expect("the fixture parses");
                serialize_boc(&roots).expect("a parsed tree serializes")
            });
        },
    );

    group.finish();
}

/// A fixed workload, run at both ends of the measurement, that touches none of this crate.
///
/// Every benchmark in a run shares one machine, and a machine that heats up reports all of
/// them as slower with nothing having changed. This does what parsing a bag does, a few
/// dozen small allocations and a walk over the bytes in them, so it moves when the machine
/// moves. A hash would not: the chip runs one on a unit of its own and reports the same
/// figure while everything around it slows down.
fn reference(c: &mut Criterion, end: &str) {
    /// The fixture is 45 cells averaging 35 bytes, so this is the shape of parsing it.
    const BLOCKS: u8 = 45;
    const EACH: usize = 35;

    let mut group = c.benchmark_group("machine");
    group.bench_function(BenchmarkId::new(end, BLOCKS), |b| {
        b.iter(|| {
            let held: Vec<Vec<u8>> = (0..BLOCKS).map(|i| vec![i; EACH]).collect();
            let total: u64 = held
                .iter()
                .flat_map(|block| block.iter())
                .map(|&byte| u64::from(byte))
                .sum();
            std::hint::black_box(total)
        });
    });
    group.finish();
}

fn before(c: &mut Criterion) {
    reference(c, "before");
}

fn after(c: &mut Criterion) {
    reference(c, "after");
}

criterion_group!(benches, before, cells, after);
criterion_main!(benches);
