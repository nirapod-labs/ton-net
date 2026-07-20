---
id: NET-ADR-001
title: One Rust core with per-language bindings, not one implementation per language
status: proposed
date: 2026-07-20
supersedes: none
superseded-by: none
---

# NET-ADR-001: One Rust core with per-language bindings, not one implementation per language

## Context

ton-net is a standalone, community-facing library: a complete TON network client
for every language, meant to become the ecosystem's reference implementation. It
is not a component of one product. Its value is correctness and breadth of
language reach, so the first architectural question is how a full network stack
reaches many languages without becoming many codebases.

The stack is thick and shared: a TL codec, an ADNL transport with an x25519
handshake and AES-256-CTR channels, a Kademlia DHT, the liteserver protocol, cell
and Merkle-proof verification, validator-signature block sync, and a TVM. All of
it parses attacker-controllable bytes off the open internet, and the proof and
signature paths are where a subtle error silently defeats the whole guarantee.

The landscape (NET-ADR-002 records it in full) shows the gap: a complete native
client exists only in Go (tonutils-go) and Python (pytoniq); the C++ reference is
LGPL and not embeddable; Rust has nothing complete; TypeScript has liteserver over
TCP but no DHT, no UDP, no proofs; Swift, Kotlin and Dart have nothing native and
fall back to an HTTP indexer or C++ FFI. No existing Rust crate can be wrapped:
everscale-network targets Everscale not TON mainnet and has no light-client layer,
ever-adnl is GPL, tycho uses QUIC rather than classic ADNL.

Three reference projects of exactly this shape were studied: signalapp/libsignal,
automerge, and matrix-rust-sdk. All three are one Rust core with thin per-language
bindings, and all three reject per-language reimplementation for shared logic.

## Decision

Implement the full TON network stack once in a Rust core, and expose it through
thin per-language bindings rather than reimplementing the wire logic in each
language.

The core is transport-generic over a sans-I/O datagram-and-stream trait. Native
runtimes (Node, mobile, CLI, server) bind tokio UDP and TCP and get the full
stack including DHT. The browser binds a WebSocket transport (it cannot open raw
sockets) and gets liteserver access through a proxy, without DHT or UDP. Bindings
are generated per target: napi-rs for Node, wasm-bindgen for the browser, UniFFI
for Swift and Kotlin, flutter_rust_bridge for Dart, pyo3 for Python.

A conformance suite of canonical byte vectors, generated against the C++ reference
node, pins the core and keeps the whole library to one observable wire behavior.

## Alternatives considered

- **Native reimplementation per language.** Rejected. This is what makes a wire
  library dangerous: N implementations of thick adversarial parsing and proof
  verification is N independent chances to mishandle a hostile packet or skip a
  signature check, and the later ones get less review than the first. Signet-style
  per-platform code works for a thin shim over an OS keystore; it is the wrong
  model for a thick, security-critical protocol stack.
- **Wrap an existing Rust crate.** Rejected because none fits: everscale-network
  is Everscale-targeted with no light-client layer, ever-adnl is GPL and
  framework-coupled, tycho is QUIC. everscale-network's Apache-2.0 ADNL internals
  are a useful reference to adapt, but the liteserver, proof, sync, and TVM layers
  must be written regardless.
- **Bind the C++ reference (`tonlib`) over FFI.** Rejected. It is LGPL, drags a
  heavy C++ build into every consumer, and does not compile to wasm. The point of
  ton-net is a small, permissive, embeddable client, not a C++ node behind FFI.
- **Pure TypeScript, or pure per-language, for the languages that lack a client.**
  Rejected as the strategy. It would fill one gap at a time and commit the project
  to a new wire implementation per language, which is the exact cost this decision
  avoids.

## Consequences

- One audited wire implementation. The security review surface is a single Rust
  crate, not six codebases in six languages.
- FFI and per-target build and distribution complexity is the accepted cost:
  prebuilt Node binaries, a wasm bundle, mobile artifacts, and Python wheels are
  real per-platform work, phased in NET-ADR-004, not delivered all at once.
- The browser cannot do UDP, so it cannot do DHT directly. This is a protocol
  fact stated plainly in the design, not engineered around.
- everscale-network's Apache-2.0 ADNL transport internals de-risk the lowest layer
  (adapt rather than write from scratch), while the liteserver, proof, sync, and
  TVM layers are original work grounded in pytoniq and the C++ reference.
- A conformance vector set and a dependency on the C++ reference as behavioral
  oracle during bring-up become maintained artifacts.

## Chain scope

ton-net is a TON-specific library by nature: it speaks TON's protocols. This is
not a Nirapod chain-agnostic core (constitution §3); it is a standalone community
library whose entire purpose is TON. A consumer that wants chain-agnostic access
puts ton-net behind its own seam. The chain-agnostic discipline applies to
Nirapod product code, not to a dedicated TON library.

## Custody and security

Custody gate: **pass, structurally.** The only keys the library holds are the
ephemeral x25519 keys for an ADNL handshake and, optionally, a throwaway client
ADNL identity. Neither is a user wallet key; both are generated per session and
discarded. The library moves and verifies bytes; it does not sign user
transactions, and a signed transaction handed to it for broadcast was signed
elsewhere. The API is shaped so a user key has nowhere to live.

Primary security surface: the whole library runs on attacker-controllable input.
The hardening targets are the TL deserializer (total, bounded, no panic; fuzzed),
Merkle-proof and cell-hash verification (a wrong level-mask or a skipped check
silently breaks the trust guarantee), and the validator-signature check in block
sync. These are covered by NET-ADR-002 and the conformance design.

## Verification

- The same resolved address, the same DHT value, the same account proof, and the
  same block-proof walk agree byte-for-byte with the C++ reference node during
  bring-up, then stand on pinned conformance vectors.
- A TL fuzz target runs in CI and does not panic, hang, or over-allocate on
  arbitrary input.
- Each binding reproduces the conformance vectors exactly in CI.
