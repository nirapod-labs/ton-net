---
id: NET-ADR-012
title: Admit lz4_flex for optional bag-of-cells compression
status: accepted
date: 2026-07-23
amends: NET-ADR-003
supersedes: none
superseded-by: none
---

# NET-ADR-012: Admit lz4_flex for optional bag-of-cells compression

## Context

v0.4.0 brings the cell engine to the capability a TON client needs, and one of the
last pieces is compressing a serialized bag of cells. TON compresses bags with LZ4,
so reproducing that means an LZ4 codec, and the Rust core has none. That reopens the
dependency question NET-ADR-003 settled for the crates it named: any crate added has
to keep one copy of each crypto crate in the tree, and has to compile to
`wasm32-unknown-unknown`, because the browser binding is first-class.

The decode side also sits on the untrusted boundary. A compressed bag arrives from a
liteserver the client does not trust, so its decompression is attacker-shaped in two
ways a plain parse is not: the code that expands it can be driven to read out of
bounds if it is written in unsafe blocks, and a small input can name a large output,
which is a decompression bomb. A codec for this boundary has to answer both.

## Decision

Add `lz4_flex`, behind an opt-in `compress` feature so the default build does not
carry it, on these lines:

| Crate | Pin | Features | Purpose |
|---|---|---|---|
| `lz4_flex` | 0.11 (0.11.6 resolved) | `default-features = false`, `safe-decode`, `safe-encode`, `std` | LZ4 block compression of a serialized bag of cells |

`lz4_flex` is pure Rust with no C, so it compiles to wasm, and its default features
are dropped to leave out the `frame` format and its `twox-hash` dependency, which the
block API this uses does not need. The `safe-decode` and `safe-encode` features hold
the codec to its bounds-checked path rather than its unsafe fast path, which is the
one the untrusted-decode boundary requires.

The single-copy rule holds. Checked 2026-07-23 with `cargo tree -d --features
compress`: `lz4_flex` is a single copy and pulls no crypto machinery, so it adds no
duplicate of `sha2`, `digest`, `crypto-common`, or `block-buffer`. It sits outside the
crypto tree tl-proto's generation fixes, so it does not reopen that constraint.

The decompression bomb is answered in the code, not the dependency: `decompress`
reads the size a compressed buffer names and refuses it before allocating if it is
past a hard cap tied to what a bag this client reads could hold, so a small input
cannot name a large allocation. This is proved in the crate's own tests rather than
asserted here.

## Consequences

- BoC compression is available under `--features compress` and absent otherwise, so
  a caller that does not need it carries neither the code nor the dependency.
- The wasm binding is unaffected: `lz4_flex` compiles to wasm, and the feature is off
  unless a binding turns it on.
- The single-copy crypto rule NET-ADR-003 fixes is unchanged, since `lz4_flex` shares
  none of that machinery.
- The untrusted-decode boundary keeps its guarantee: decompression is bounds-checked
  and capped, so a hostile compressed bag fails by returning rather than by reading
  out of bounds or exhausting memory.
