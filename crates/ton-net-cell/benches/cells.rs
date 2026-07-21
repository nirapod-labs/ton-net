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
use ton_net_cell::{parse_boc, serialize_boc};

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
            b.iter(|| serialize_boc(std::hint::black_box(roots)).expect("a parsed tree serializes"))
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
            })
        },
    );

    group.finish();
}

criterion_group!(benches, cells);
criterion_main!(benches);
