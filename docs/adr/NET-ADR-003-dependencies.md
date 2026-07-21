---
id: NET-ADR-003
title: Depend on tl-proto and keep one copy of each crypto crate
status: proposed
date: 2026-07-20
supersedes: none
superseded-by: none
amended-by: NET-ADR-007
---

# NET-ADR-003: Depend on tl-proto and keep one copy of each crypto crate

> Amended by [NET-ADR-007](NET-ADR-007-signature-verification.md), which extends
> `curve25519-dalek`'s purpose here to ed25519 signature verification and adds
> `ed25519-dalek` as a development dependency for differential testing. The
> single-copy rule below is unchanged, and is what forced that decision.

## Context

The Rust core needs a TL codec, a few crypto primitives, an async runtime with UDP
and TCP, and a JSON parser for the config, and all of it must compile to both native
and `wasm32-unknown-unknown` because the browser target is a first-class binding.
Crate choice is a real decision here for three reasons: crypto correctness, wasm
compatibility, and binary size.

The binary-size reason has teeth. If two crates in the tree pull different major
versions of the same crypto machinery, Cargo compiles both, and the wasm bundle
carries two copies of, for example, `sha2` with its `digest` and `block-buffer`
support. The governing rule for crypto crates is therefore: one version of each in
the tree.

tl-proto sets the generation. As of 0.5.4 (2025-10-28) tl-proto depends on `sha2
0.10`, which sits on `crypto-common 0.1`, `digest 0.10`, and `block-buffer 0.10`.
Any crypto crate this core adds shares the tree with tl-proto, so a crate that has
moved to the newer `crypto-common 0.2` generation (`sha2 0.11`, `aes 0.9`, `ctr
0.10`) would duplicate that machinery. This is verified with `cargo tree -d`: adding
`sha2 0.11` beside tl-proto produces two `sha2`, two `digest`, two `crypto-common`,
and two `block-buffer` in the tree.

`curve25519-dalek` is the exception. tl-proto does not depend on it, so its version
is this core's to choose freely, and bumping it duplicates nothing.

## Decision

Use tl-proto for the TL codec, and pin each crypto crate to the version that keeps a
single copy in the tree. Versions current 2026-07-20.

| Crate | Pin | Purpose |
|---|---|---|
| `tl-proto` | 0.5.4 | TON TL wire codec (boxed/bare, CRC32 ids, derive) |
| `curve25519-dalek` | 5.x | ed25519 public keys and x25519 ECDH for ADNL, via the Edwards and Montgomery clamped operations directly |
| `sha2` | 0.10.x | SHA-256 and SHA-512 (ADNL ids and key derivation, cell hashes) |
| `aes` | 0.8.x | AES-256 for the ADNL cipher (constant-time, third-party audited) |
| `ctr` | 0.9.x | CTR mode over AES |
| `tokio` | 1.x (`sync`, `macros` only on wasm) | native async, UDP, TCP |
| `thiserror` | 2.x | library error enums |
| `serde` + `serde_json` | 1.x | global-config parsing |
| `getrandom` | 0.2+ (wasm feature per version) | CSPRNG seed for ephemeral keys |
| `zeroize` | 1.x | wipe ephemeral secrets |

`sha2`, `aes`, and `ctr` are held at the `crypto-common 0.1` generation because that
is tl-proto's generation; moving any of them to the newer generation splits the
crypto machinery into two copies (see the alternatives). `curve25519-dalek` is taken
at its current major (5.x) because tl-proto does not pull it, so it stays a single
copy regardless, and 5.x is the current maintained line.

The ADNL ed25519-to-x25519 conversion is done directly with curve25519-dalek: the
client public key is `EdwardsPoint::mul_base_clamped` over the derived scalar, and
the shared secret is `MontgomeryPoint::mul_clamped` over the server key's Montgomery
form. This needs neither `ed25519-dalek` nor `x25519-dalek` as separate
dependencies, which keeps the crypto surface to one curve crate. It is verified
against a TON mainnet liteserver in `spikes/adnl-feasibility`.

The node binding uses napi-rs 3.x (`napi`, `napi-derive`, `napi-build`); its version
and reasoning sit in NET-ADR-004.

Feed tl-proto the official TON schema files (`ton_api.tl`, `lite_api.tl` from
`ton-blockchain/ton`), not Everscale's, wherever the forks diverged.

## Alternatives considered

- **Roll our own TL codec.** Rejected. tl-proto implements the exact wire format
  (CRC32-IEEE ids, boxed/bare, bytes/vector encoding), is pure-Rust and wasm-safe,
  and is proven against TON mainnet by tonstack/lite-client and used inside tycho.
  Rewriting it duplicates a solved, tested problem and adds a serialization bug
  surface for no gain. The feasibility spike hand-rolls TL only to prove the wire
  format from first principles; the library uses tl-proto.
- **The newer RustCrypto generation (`sha2 0.11`, `aes 0.9`, `ctr 0.10`).** Rejected
  for now. These sit on `crypto-common 0.2`, `digest 0.11`, and `cipher 0.5`, while
  tl-proto 0.5.4 still pins `sha2 0.10` on `crypto-common 0.1`. `cargo tree -d`
  confirms that adopting them beside tl-proto duplicates `sha2`, `digest`,
  `crypto-common`, and `block-buffer`. The single-copy rule wins; revisit when
  tl-proto migrates to the `digest 0.11` generation.
- **Hold `curve25519-dalek` at 4.x too.** Rejected. tl-proto does not depend on it,
  so 5.x stays a single copy and duplicates nothing; 5.x is the current maintained
  line and is verified against mainnet with the exact clamped operations this core
  uses. The cost is a higher MSRV, accepted below.
- **`ring` for crypto.** Rejected. It ships C and per-arch assembly and does not
  compile cleanly to `wasm32-unknown-unknown`, which disqualifies it against the hard
  browser requirement. Pure-Rust RustCrypto plus dalek is the correct call, the same
  one libsignal, Zcash, and tonstack make.
- **`ed25519-dalek` plus `x25519-dalek` for the ADNL keys.** Rejected as separate
  dependencies. The conversion is a few lines directly on curve25519-dalek, which
  keeps the curve crate to one dependency instead of three.
- **`async-trait` for the transport seam.** Rejected. The transport is a generic
  `T: Transport` with native `async fn` in the trait, not a boxed `dyn Transport`, so
  no `async-trait` allocation or dependency is needed (NET-ADR-004, the v0.1.0 plan).

## Consequences

- The crypto tree is single-copy: one each of curve25519-dalek, sha2, digest,
  crypto-common, aes, and ctr. `cargo tree -d` confirms no crypto crate is
  duplicated, and the wasm bundle carries one copy of each primitive.
- The stack is proven against TON mainnet, not assembled from documentation: the
  feasibility spike completes the ADNL handshake and reads the masterchain head on
  exactly these crate lines (curve25519-dalek 5.x with sha2 0.10, aes 0.8, ctr 0.9).
- MSRV rises to 1.85 for the core, set by curve25519-dalek 5.x. The node binding
  requires 1.88 through napi-rs 3.x, carried by the binding crate rather than the
  core.
- Holding sha2, aes, and ctr at tl-proto's generation is a deliberate, dated choice
  with a documented trigger to revisit: when tl-proto moves to `digest 0.11`, the
  whole RustCrypto set moves with it in one step.
- `aes` carries a third-party audit; `sha2`, `ctr`, and the dalek crates are the
  constant-time de-facto standard but without a separately cited audit. This is
  recorded, not glossed.
- wasm carries known gotchas the system design handles: `getrandom` needs its wasm
  feature (name varies by version), tokio's net and time do not build on wasm (use a
  WebSocket transport), and futures are `!Send`.

## Chain scope

TON-specific (see NET-ADR-001). tl-proto and the TON schema files are TON's wire
format.

## Custody and security

The library holds no user keys. The dependency choice is itself a security
decision: constant-time, audited-where-possible, memory-safe pure-Rust crypto, no
C or assembly, `zeroize` on ephemeral secrets, and one audited copy of each
primitive rather than two.

## Verification

- `cargo tree -d` shows no duplicated crypto crate, and `cargo tree -i` shows a
  single version each of curve25519-dalek, sha2, digest, crypto-common, aes, and ctr.
  Confirmed 2026-07-20.
- The feasibility spike completes the ADNL handshake and reads a plausible
  masterchain head from a TON mainnet liteserver on the pinned crate lines.
- The core builds and its tests pass on both native and `wasm32-unknown-unknown`.
- The TL codec round-trips the conformance vectors byte-for-byte against the
  reference node.
