---
id: NET-ADR-010
title: BoC compression behind a feature, on the untrusted boundary
status: accepted
date: 2026-07-23
supersedes: none
superseded-by: none
---

## Context

TON compresses a serialized bag of cells with LZ4, and a full client reads and writes that
form. Supporting it costs one compression dependency and a decode path that runs on bytes a
peer chose. That path is an untrusted boundary: a small compressed input names how many bytes
it expands to, and a decoder that trusts the named length can be told to allocate far more
memory than the input's size suggests.

NET-ADR-003 places the whole client surface in scope, and the LZ4-compressed bag is part of
that surface. NET-ADR-004 governs which dependencies enter and holds the crypto and codec
lines to a single copy each, so a compression crate is admitted under that policy and must
leave the single-copy crypto requirement intact. NET-ADR-001 fixes the consumer priority:
indexer and node scale is the demanding consumer that wants compressed bags, the wallet and
mobile path does not, and scale breadth is carried as an isolated, feature-gated path that
costs a lighter consumer nothing at runtime.

## Decision

Add LZ4 compression of a serialized bag of cells behind a Cargo feature named `compress`, off
the default build.

The crate is `lz4_flex`, pinned at 0.11, with `default-features = false` and the features
`safe-decode`, `safe-encode`, and `std`. It is pure Rust, needs no C toolchain, and pulls no
crypto machinery. `compress = ["dep:lz4_flex"]` makes the dependency optional and the feature
the only thing that pulls it. The default build carries neither the code nor the crate:
`mod compress` in `crates/ton-net-cell/src/boc.rs` and the crate-level re-export in `lib.rs`
both sit behind `#[cfg(feature = "compress")]`.

The module `crates/ton-net-cell/src/boc/compress.rs` exposes four functions. `compress` takes
the bytes `serialize_boc` produces and returns the LZ4 block form with the original length
prepended. `decompress` reverses it. `compress_boc` and `decompress_boc` do serialize-then-
compress and decompress-then-parse in one step.

The decode side is treated as an untrusted boundary, with three rules on it:

1. The compressed form names the length it expands to. `lz4_flex` prepends that length as
   four little-endian bytes.
2. `decompress` reads that named length and refuses it before allocating. The named length is
   checked against a hard cap, `MAX_DECOMPRESSED`, defined as `64 << 20`, which is 64 MiB
   (67,108,864 bytes). A length past the cap returns
   `CellError::Malformed("compressed bag expands past the cap")` before the decoder runs.
   Bytes too short to name a length return `CellError::Truncated`. A small hostile input
   cannot name a large allocation.
3. The expansion runs on `lz4_flex`'s bounds-checked safe-decode path
   (`decompress_size_prepended`, reached through `default-features = false` plus the
   `safe-decode` feature, not the crate's unsafe fast path). Bytes that are not valid LZ4, or
   that do not expand to the length they name, return
   `CellError::Malformed("bytes are not valid lz4")`.

The cap sits above what the largest readable bag needs and still bounds the allocation.
`parse_boc` refuses a bag with more than `MAX_CELLS` cells (`1 << 17`, 131,072), and every
cell costs at least a couple of bytes on the wire, so a bag that would expand past 64 MiB
could not parse anyway. The cap is what a decompressor may allocate before that cell-count
check runs.

## Alternatives considered

- Compression always on, in the default build. Rejected. It puts `lz4_flex` in every
  artifact, including the mobile and wallet builds that never read a compressed bag, against
  the rule that scale breadth costs a lighter consumer nothing at runtime (NET-ADR-001).
- No compression at all. Rejected. TON uses LZ4-compressed bags, and a client that cannot
  read them is incomplete against the whole-surface scope of NET-ADR-003.
- A decoder that trusts the named length with no pre-allocation cap. Rejected. The named
  length is attacker-chosen, so a few compressed bytes can name a very large size, and a
  decoder that allocates the named size first becomes a denial-of-service primitive. The
  cap-before-allocate check is the reason to place the boundary here.
- The crate's unsafe fast decode path. Rejected. The decode side reads bytes from a peer the
  client does not trust, and the bounds-checked path is the safety floor for that input.
  Correctness and safety rank above speed, and the safe path is selected explicitly through
  `default-features = false` plus `safe-decode`.
- A C-backed LZ4 binding. Rejected. It would add a C toolchain and break the single-language,
  wasm-clean posture. `lz4_flex` is pure Rust.

## Consequences

- The default build is unchanged: no `lz4_flex`, no compression code, the same binary. A
  consumer that wants compressed bags turns on the `compress` feature and pays for it only
  then.
- One dependency enters the tree under the feature. `lz4_flex` pulls no crypto machinery, so
  the single-copy crypto tree NET-ADR-004 fixes is untouched.
- cargo-deny admits `lz4_flex` under the existing `deny.toml` policy with no new exception. It
  resolves to a single copy, so it needs no entry in the duplicate skip list that
  `multiple-versions = "deny"` would otherwise require, and it comes from the crates.io
  registry the policy allows. No skip entry, allowed-license, or advisory-ignore change was
  made for it.
- The decode boundary is explicit and bounded. A hostile input is capped before allocation,
  and malformed or truncated input returns a typed error rather than panicking or
  over-allocating.
- The cap is a fixed 64 MiB ceiling. A legitimate bag never approaches it because `MAX_CELLS`
  bounds it first, so the cap constrains only hostile input.

## Chain scope

TON only. The LZ4-compressed bag of cells is a TON form. ton-net stays TON-specific, and
nothing here reaches toward another chain.

## Custody and security

No keys, no funds, no signing, no recovery. The module compresses and decompresses cell bags;
it holds no secret and moves no value. Custody is not touched.

The security surface is the decode path, and it is an untrusted boundary by design. The
properties the code holds:

- Cap before allocation. The named expansion length is read and rejected against
  `MAX_DECOMPRESSED` before `decompress_size_prepended` allocates, so a small input cannot
  drive a large allocation.
- Bounds-checked expansion. Decoding runs on `lz4_flex`'s safe-decode path, selected through
  `default-features = false` and the `safe-decode` feature, not the crate's unsafe path.
- Typed failure. Truncated, over-cap, and invalid-LZ4 inputs return `CellError::Truncated` or
  `CellError::Malformed`, never a panic or an unbounded allocation.
- Single-copy crypto preserved. `lz4_flex` is not a crypto primitive and pulls none, so the
  single-copy crypto tree of NET-ADR-004 is unchanged.

These are properties the code shows, not aspirations.

## Verification

- Tests in `crates/ton-net-cell/src/boc/compress.rs` cover: a two-cell bag round-trips
  through `compress_boc` and `decompress_boc`; `compress` and `decompress` are inverse on
  bytes; a bag whose length prefix is forged to `MAX_DECOMPRESSED + 1` is refused with
  `CellError::Malformed("compressed bag expands past the cap")` before allocation; bytes with
  a valid prefix but an invalid LZ4 body return `CellError::Malformed("bytes are not valid
  lz4")`; and bytes too short to name a length return `CellError::Truncated`.
- `cargo deny check` admits `lz4_flex` under `deny.toml` with no new exception.
- The feature gate holds at build time. `mod compress` and the crate-level re-export are
  behind `#[cfg(feature = "compress")]`, and `compress = ["dep:lz4_flex"]` is the only path
  that pulls the crate, so a default build compiles without it.
