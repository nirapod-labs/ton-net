---
id: NET-ADR-003
title: Depend on tl-proto and the mature RustCrypto lines, not the newest releases
status: proposed
date: 2026-07-20
supersedes: none
superseded-by: none
---

# NET-ADR-003: Depend on tl-proto and the mature RustCrypto lines, not the newest releases

## Context

The Rust core needs a TL codec, four crypto primitives, an async runtime with UDP
and TCP, and a JSON parser for the config, and all of it must compile to both
native and `wasm32-unknown-unknown` because the browser target is a first-class
binding. Crate choice is a real decision here for three reasons: crypto
correctness, wasm compatibility, and binary size.

Two weeks before this decision (2026-07-06) the dalek crates jumped to 3.0 / 5.0
and RustCrypto shipped sha2 0.11 / aes 0.9. The whole TON-Rust ecosystem, and the
gold-standard reference libsignal, are still on the older lines. Mixing new and
old forces Cargo to compile two copies of curve25519-dalek and sha2, which
inflates the wasm bundle.

The choice was validated against real TON-mainnet Rust code: tonstack/lite-client,
which talks to TON mainnet liteservers, uses exactly tl-proto + x25519-dalek 2.0.1
+ tokio + thiserror. The stack below is proven against mainnet, not assembled from
guesses.

## Decision

Pin the mature dependency lines, and use tl-proto for TL rather than rolling a
codec. Concrete selection (versions current 2026-07-20, revisit the crypto lines
in 6 to 12 months once tl-proto and everscale-crypto migrate):

| Crate | Pin | Purpose |
|---|---|---|
| `tl-proto` | 0.5.4 | TON TL wire codec (boxed/bare, CRC32 ids, derive) |
| `ed25519-dalek` | 2.2.0 | Ed25519 identity keys |
| `x25519-dalek` | 2.0.1 (`static_secrets`) | X25519 ECDH for ADNL |
| `curve25519-dalek` | 4.1.3 (transitive) | field ops, ed25519 to x25519 conversion |
| `sha2` | 0.10.9 | SHA-256 (ADNL ids, cell hashes) |
| `aes` | 0.8.4 | AES-256 for ADNL cipher (constant-time, audited) |
| `ctr` | 0.9.2 | CTR mode over AES |
| `tokio` | 1.53 (`sync`,`macros` only on wasm) | native async, UDP, TCP |
| `async-trait` | 0.1.91 | object-safe `dyn Transport` across native and wasm |
| `thiserror` | 2.0 | library error enums |
| `serde` + `serde_json` | 1.0 | global-config parsing |
| `getrandom` | 0.2 (`js` feature on wasm) | CSPRNG seed, version tied to the rand line |
| `zeroize` | 1.8+ | wipe ephemeral secrets |

Feed tl-proto the official TON schema files (`ton_api.tl`, `lite_api.tl` from
`ton-blockchain/ton`), not Everscale's, wherever the forks diverged. The ADNL
ed25519-to-x25519 conversion is done directly via curve25519-dalek's
Edwards-to-Montgomery conversion (about thirty lines, keeps one curve25519-dalek
copy) rather than pulling the stale everscale-crypto helper.

## Alternatives considered

- **Roll our own TL codec.** Rejected. tl-proto implements the exact wire format
  (CRC32-IEEE ids, boxed/bare, bytes/vector encoding), is pure-Rust and wasm-safe,
  and is proven against TON mainnet by tonstack/lite-client and used inside tycho.
  Rewriting it duplicates a solved, tested problem and adds a serialization bug
  surface for no gain. tl-proto is the codec; TON's schema files are the input.
- **The newest crypto lines (dalek 3.0, sha2 0.11, aes 0.9).** Rejected for now.
  They bump MSRV, have near-zero ecosystem uptake, and force duplicate
  curve25519-dalek and sha2 copies against tl-proto's digest 0.10, inflating the
  wasm bundle. Revisit once the TON-Rust ecosystem migrates.
- **`ring` for crypto.** Rejected. It ships C and per-arch assembly and does not
  compile cleanly to `wasm32-unknown-unknown`, which disqualifies it against the
  hard browser requirement. Pure-Rust RustCrypto plus dalek is the correct call,
  the same one libsignal, Zcash and tonstack make.
- **everscale-crypto for the ADNL key conversion.** Rejected as a dependency. It
  is stale (2024-11), pulls rand 0.8 and getrandom 0.2, and drags Everscale
  framework crates; the conversion is small enough to do directly.

## Consequences

- The whole stack is proven against TON mainnet (tonstack) rather than assembled
  from documentation, which de-risks bring-up substantially.
- One shared copy of curve25519-dalek and sha2 across the tree, keeping the wasm
  bundle small.
- The mature-line pin is a deliberate, dated choice with a documented revisit
  window; it is not neglect.
- `aes` carries a third-party audit; `sha2`, `ctr` and the dalek crates are the
  constant-time de-facto standard but without a separately cited audit. This is
  recorded, not glossed. If a cited audit becomes a hard requirement, it is
  verified independently.
- wasm carries known gotchas that the system design must handle: `getrandom` needs
  its wasm feature (name varies by version), tokio's net and time do not build on
  wasm (use `wasm-bindgen-futures` and `gloo-timers`), and futures are `!Send`
  (use `#[async_trait(?Send)]`).

## Chain scope

TON-specific (see NET-ADR-001). tl-proto and the TON schema files are TON's wire
format.

## Custody and security

Custody gate: pass (no keys). The dependency choice is itself a security decision:
constant-time, audited-where-possible, memory-safe pure-Rust crypto, no C or
assembly, `zeroize` on ephemeral secrets.

## Verification

- The core builds and its tests pass on both native and `wasm32-unknown-unknown`.
- `cargo tree -i getrandom` and `-i curve25519-dalek` show a single version each,
  confirming no duplicate crypto copies.
- The TL codec round-trips the conformance vectors (NET-ADR-004 conformance)
  byte-for-byte against the reference node.
