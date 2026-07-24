---
id: NET-ADR-004
title: Vetted dependencies, and one copy of each crypto primitive
status: accepted
date: 2026-07-23
supersedes: none
superseded-by: none
---

# NET-ADR-004: Vetted dependencies, and one copy of each crypto primitive

## Context

The client verifies every answer against validator signatures and reads bytes from peers it
does not trust, so the crypto it depends on sits on the trust path, and the codec that parses
those bytes sits next to it. The library also ships prebuilt across language bindings, so both
the size of an artifact and the number of copies of a primitive inside one artifact count. Two
generations of the same curve or digest in a single binary is a wider surface to audit and to
patch on an advisory, and a larger file to distribute.

No record fixed which crates supply the cryptographic primitives, how many copies of each the
tree may hold, or what may enter the default build. Absent that, an ordinary dependency bump
can add a second copy of the signature curve or the digest, or pull an unvetted or
non-redistributable crate, with nothing to catch it. This record fixes the dependency policy
that the one-audited-core architecture (NET-ADR-002) rests on.

## Decision

1. **The primitives come from established crates.** The signature curve, the digest, the
   stream cipher, and the key exchange are taken from published, reviewed crates, not written
   in this repository. The curve is `curve25519-dalek` (`5`), which serves both ed25519
   verification in the block crate and the x25519 key exchange in the ADNL handshake. The
   digest is `sha2` (`0.10`), used for the cell representation hash, the validator short id,
   and the ed25519 and handshake hashing. The stream cipher is `aes` (`0.8`) driven in counter
   mode by `ctr` (`0.9`), the ADNL transport cipher. Session randomness at the I/O edge is
   `getrandom` (`0.4`). The TL codec is `tl-proto` (`0.5`). Error types are `thiserror` (`2`).

2. **One copy of each primitive across the tree.** `deny.toml` sets
   `[bans] multiple-versions = "deny"`, so any second version of any crate fails the gate. The
   shipped tree resolves to a single `curve25519-dalek`, a single `sha2`, a single `aes`, a
   single `ctr`, and a single `getrandom`. Signature verification is built on the curve crate
   already present for the key exchange rather than on a separate ed25519 crate, which would
   duplicate the curve (the verification rule itself is NET-ADR-006).

3. **The one production duplicate is named, not hidden.** The RustCrypto trait machinery
   (`block-buffer`, `cpufeatures`, `crypto-common`, `digest`) sits at two generations in every
   artifact, because `curve25519-dalek` `5` moved to the `digest` `0.11` line while `tl-proto`
   `0.5` still reaches `sha2` on the `digest` `0.10` line. Holding this workspace's own `sha2`
   at `0.10` keeps the split to one extra copy rather than three. It resolves when `tl-proto`
   crosses, and not before. `syn` also appears at two generations, build-time only, linked into
   no shipped artifact. Each duplicate is listed on its own line in `deny.toml` with its reason;
   there is no `skip-tree`, so a seventh entry is a decision somebody makes.

4. **A minimal surface: default features off, take only what is used.** `tokio` is pulled with
   `default-features = false`, and each crate opts into only the features it needs; the core
   crate takes only the timer, and the socket and runtime come from the caller, which is the
   sans-I/O seam of NET-ADR-002. `lz4_flex` (`0.11`) is pulled with default features off on its
   bounds-checked safe-decode and safe-encode path, no C and wasm-clean. The benchmark harness
   `criterion` (`0.8`) and the property-test crate `proptest` (`1`) are dev-dependencies with
   default features off, so their heavier trees never enter a shipped build.

5. **Heavy or non-core dependencies stay behind features, off the default build.** The cell
   crate gates two: `json` pulls `serde_json` for rendering a cell tree, and `compress` pulls
   `lz4_flex` for a serialized bag of cells. Both are off by default. `serde_json` is already in
   the tree for config parsing, so `json` admits a new use of an existing dependency, not a new
   one; `compress` admits `lz4_flex`, the compression path of NET-ADR-010. The Node.js binding
   (`napi`, `napi-derive`, `napi-build`) is a separate, unpublished workspace member, so a Rust
   consumer of the core never pulls the binding runtime (thin bindings, NET-ADR-002).

6. **Everything is vetted the same way, at the gate.** `cargo-deny` answers three questions a
   build does not: whether anything in the tree carries a published advisory
   (`yanked = "deny"`, with an empty ignore list, so a withdrawn or advised release fails),
   whether every license can be redistributed under this project's Apache-2.0 (a short
   allow-list of permissive licenses), and whether any crate arrived from somewhere other than
   crates.io (unknown registries and git sources denied). It runs in CI and in the justfile.

## Alternatives considered

- **Hand-write the curve, digest, or cipher.** Rejected. A hand-rolled primitive on the trust
  path is unaudited code with no advisory channel. Established crates carry the review and the
  channel; cleverness belongs in the system design, not in the primitives.
- **Add an ed25519 crate to the shipped tree for signature verification.** Rejected. The curve
  is already present for the key exchange, so a second crate duplicates it. `ed25519-dalek`
  (`3`) stays a dev-only differential oracle in the block crate, grading this crate's acceptance
  rule against an audited implementation; it does not ship and reaches no consumer.
- **Follow `curve25519-dalek` to the `digest` `0.11` line for the workspace's own `sha2`.**
  Rejected while `tl-proto` still reaches the `0.10` line: it would put the machinery at three
  copies rather than two. Revisited when `tl-proto` crosses.
- **Cover the crypto stack with a `skip-tree` in `cargo-deny`.** Rejected. A tree would swallow
  an unrelated duplicate without saying so. Each exception is named individually so that adding
  one is visible.
- **Pull `tokio` with default features, or place a runtime in the core.** Rejected. The
  sans-I/O seam keeps the runtime at the caller (NET-ADR-002); the core takes only the timer to
  bound a call.
- **Ship `serde_json` and `lz4_flex` in the default build.** Rejected. JSON rendering and bag-of-
  cells compression are opt-in, so the default build carries neither by obligation.

## Consequences

- A dependency bump that introduces a second copy of a primitive fails `cargo deny` at the
  gate, not at runtime. The single-copy rule decays silently as crates move, and this is what
  keeps it honest.
- The crypto audit surface is one implementation per primitive, and one advisory feed to watch
  per primitive.
- The `digest` split is a standing item, not a defect. It closes when `tl-proto` crosses to the
  `0.11` line; until then the skip list carries the reason.
- The default build stays small: no `serde_json` obligation from the cell crate, no `lz4_flex`,
  no benchmark or test tree, no binding runtime. A consumer pays for JSON, compression, or the
  binding only by asking for it.
- A copyleft or source-available license entering the tree fails the gate rather than landing
  as a silent bump, so admitting one is a recorded decision.

## Chain scope

TON-specific (NET-ADR-002). The TL codec and the ADNL crypto are TON's wire format and
transport; the curve, digest, and ciphers are what TON's block signatures and channel require.
No dependency here reaches another chain, and composing chains lives above ton-net.

## Custody and security

No user keys. The dependency policy touches no key material and does not change the custody
position. Its security value is the trust base it fixes: the crypto that verifies validator
signatures (NET-ADR-006) and secures the ADNL channel is established, single-copy code with a
live advisory feed, not hand-written and not duplicated. `yanked = "deny"` with an empty ignore
list means a withdrawn or advised release stops the build. On the untrusted boundary, `lz4_flex`
decodes through its bounds-checked safe path with no C. Performance is taken within the safety
floor, never through an unsafe or unauditable dependency shortcut (NET-ADR-001).

## Verification

- `cargo deny check` runs in CI and in the justfile, enforcing advisories, licenses, the
  single-copy ban, and the crates.io-only source rule against the full-feature graph.
- The single-copy invariant is observable in the lockfile: `curve25519-dalek`, `aes`, `ctr`,
  and the shipped `sha2` and `getrandom` each resolve to one version. The only recorded
  duplicates are the RustCrypto trait machinery at two generations and `syn` at build time,
  each named in `deny.toml` with its reason. The dev-only differential oracle and property-test
  crates pull second copies that do not ship.
- The signature acceptance rule is graded against the audited `ed25519-dalek` in a differential
  test that does not ship (NET-ADR-006).
- `cargo-about` regenerates the third-party license inventory from the resolved tree, so the
  redistribution position is checked, not asserted.
