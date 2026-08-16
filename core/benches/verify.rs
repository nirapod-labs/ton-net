// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Nirapod Labs

//! What verification costs, over a real mainnet proof chain.
//!
//! A first sync walks over a thousand links, and every link rebuilds a validator set
//! from its source key block's configuration and then checks signatures against it until
//! two thirds of the weight is carried. Those two dominate the walk, so they are the
//! numbers worth watching: a change that makes a link ten microseconds slower costs a
//! cold sync ten milliseconds, and one that makes it ten milliseconds slower costs ten
//! seconds.
//!
//! The fixture is a captured `liteServer.getBlockProof` answer, so this runs offline.

use criterion::{criterion_group, criterion_main, Criterion};
use ton_net_block::{verify_chain, BlockIdExt, PartialBlockProof};
use ton_net_tl::deserialize;

/// Three forward links from masterchain 46894135, crossing a validator-set rotation.
const CHAIN: &str = include_str!("../tests/fixtures/chain.hex");

fn decode(text: &str) -> PartialBlockProof {
    let hex: String = text
        .lines()
        .filter(|line| !line.starts_with('#'))
        .flat_map(str::chars)
        .filter(|c| !c.is_whitespace())
        .collect();
    let bytes: Vec<u8> = (0..hex.len() / 2)
        .map(|i| u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).expect("the fixture is hex"))
        .collect();
    deserialize(&bytes).expect("the fixture decodes")
}

fn anchor(proof: &PartialBlockProof) -> BlockIdExt {
    proof.from.clone()
}

fn verification(c: &mut Criterion) {
    let proof = decode(CHAIN);
    let from = anchor(&proof);

    let mut group = c.benchmark_group("chain");
    // Three links, so the per-link cost is a third of what this reports. A cold sync
    // against mainnet in July 2026 was 1244 of them.
    group.sample_size(20);
    group.bench_function("verify three links", |b| {
        b.iter(|| {
            verify_chain(std::hint::black_box(&from), std::hint::black_box(&proof))
                .expect("the fixture verifies")
        });
    });
    group.finish();
}

criterion_group!(benches, verification);
criterion_main!(benches);
