// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Nirapod Labs

//! What a dictionary costs to build and to read.
//!
//! A wallet reaches its state through dictionaries, and a proof check rebuilds one to hold
//! it to a root hash, so the write path is on the hot path as much as the read. Building a
//! dictionary is where the work is: every set descends, may split a node, and rebuilds the
//! label of every fork above it in its one canonical form. This measures that against a read
//! of the same keys, over a few sizes, so a change that makes construction quadratic shows
//! up here.

use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};
use ton_net_cell::{Builder, Dict};

/// `n` distinct 256-bit keys, the width an account dictionary uses.
fn keys(n: u32) -> Vec<[u8; 32]> {
    (0..n)
        .map(|i| {
            let mut key = [0u8; 32];
            key[28..].copy_from_slice(&i.to_be_bytes());
            key
        })
        .collect()
}

/// A small value every key is stored under.
fn value() -> Builder {
    let mut builder = Builder::new();
    builder.store_uint(0xdead_beef, 32).expect("a value fits");
    builder
}

/// A dictionary holding every key.
fn build(keys: &[[u8; 32]]) -> Dict {
    let mut dict = Dict::new(256).expect("a sane key width");
    let value = value();
    for key in keys {
        dict.set(key, &value).expect("a set fits");
    }
    dict
}

fn dict(c: &mut Criterion) {
    let mut group = c.benchmark_group("dict");
    for &n in &[64u32, 256, 1024] {
        let keys = keys(n);

        // Building the whole dictionary from its keys, the write path a proof rebuild pays.
        group.bench_with_input(BenchmarkId::new("build", n), &keys, |b, keys| {
            b.iter(|| build(std::hint::black_box(keys)));
        });

        // Looking every key back up, the read path.
        let dict = build(&keys);
        group.bench_function(BenchmarkId::new("get", n), |b| {
            b.iter(|| {
                for key in &keys {
                    std::hint::black_box(dict.get(key).expect("a lookup succeeds"));
                }
            });
        });
    }
    group.finish();
}

criterion_group!(benches, dict);
criterion_main!(benches);
