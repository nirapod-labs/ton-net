# Architecture

One Rust core that speaks TON's full client protocol, exposed through thin
per-language bindings. This document is the map: the layer stack, why the
transport is a seam, how one core serves every language, and where the trust
guarantee lives.

Governing decisions: [NET-ADR-001](adr/NET-ADR-001-architecture.md) through
[NET-ADR-005](adr/NET-ADR-005-tvm.md). Design:
[system design](design/system-design.md). Wire detail:
[protocol/wire-format.md](protocol/wire-format.md).

---

## The stack

```
┌──────────────────────────────────────────────────────────────┐
│  Consumers  (not in this repo)                                │
│  wallets · explorers · indexers · node tooling · research     │
└───────────────▲──────────────────────────────────────────────┘
                │  small, closed, typed API
┌───────────────┴──────────────────────────────────────────────┐
│  Bindings   napi · wasm · uniffi · flutter · pyo3             │
│  two layers each: generated raw + hand-written idiomatic      │
└───────────────▲──────────────────────────────────────────────┘
                │
┌───────────────┴──────────────────────────────────────────────┐
│  TVM              local get-method execution over proven state │
├──────────────────────────────────────────────────────────────┤
│  Block-sync       pinned anchor · getBlockProof · 2/3 sigs     │
├──────────────────────────────────────────────────────────────┤
│  Proof engine     cell/BoC · exotic cells · check_*_proof      │
├───────────────────────────────┬──────────────────────────────┤
│  Liteserver client            │  DHT client                   │
│  liteServer.* over ADNL-TCP    │  Kademlia over ADNL-UDP        │
├───────────────────────────────┴──────────────────────────────┤
│  ADNL channel     handshake · AES-256-CTR · framing · seqno    │
├──────────────────────────────────────────────────────────────┤
│  TL codec (tl-proto)          CRC32-tagged (de)serialization   │
├───────────────┬──────────────────────────────────────────────┤
│  Transport     │  Crypto primitives                           │
│  (trait)       │  x25519 · ed25519 · sha256 · aes-ctr          │
│  TCP·UDP·WS    │                                              │
└───────────────┴──────────────────────────────────────────────┘
```

Each layer has one job. The TL codec knows the schema, not sockets. The ADNL
channel owns encryption and calls a transport. The liteserver and DHT clients
compose channels and the codec. The proof engine turns a response plus a trusted
hash into a verified value. Block-sync produces that trusted hash. The TVM runs
over what the proof engine has verified. The separation is what lets the transport
swap underneath and one core serve every language.

---

## Why the transport is a seam

The most consequential design line: the core talks to a `Transport` trait, not a
socket. This is the matrix-rust-sdk store-trait pattern applied to networking.

DHT and ADNL-UDP need datagrams to arbitrary peers, which means UDP. Liteservers
need a stream, which means TCP. The browser can do neither: a web page cannot open
a raw UDP or TCP socket at all. Baking sockets into the core would make it not
exist in a browser.

With a trait at the seam, the same protocol logic runs everywhere and each runtime
supplies the transport it can:

| Runtime | UDP | TCP | Transports | DHT | Liteserver |
|---|---|---|---|---|---|
| Node / server / CLI | yes | yes | tokio UDP + TCP | full | direct |
| iOS / Android | yes | yes | native UDP + TCP | full | direct |
| Flutter / RN | yes | yes | via host | full | direct |
| Browser | no | no | WebSocket only | none | via a proxy |

The browser row is the honest one. In a browser there is no raw socket, so DHT and
UDP are simply unavailable, and liteserver access runs only through a
WebSocket-to-liteserver proxy. This is a protocol fact, stated, not engineered
around.

The core is **sans-I/O**: the protocol and state logic never touch a socket
directly, so the identical code runs over tokio on native and over WebSocket on
wasm. Transport is the only thing that changes between targets.

---

## Why one core, not one per language

The TON client stack is thick shared logic on hostile input: a TL codec, an
encrypted handshake, a Kademlia loop, cell and Merkle-proof verification, a
signature-checked sync, and a TVM. Reimplementing that per language is
reimplementing the same adversarial-parsing and proof-verification risk per
language, and the later copies get less review than the first.

So the core is Rust: memory-safe, fast, wasm-capable, with the vetted crypto
crates (NET-ADR-003). Every language gets the same audited behavior through a
binding that adds nothing. The reference projects that took this path,
signalapp/libsignal, automerge, and matrix-rust-sdk, all did so for the same
reason: shared security-critical logic belongs in one place.

The cost, stated: FFI and per-target distribution (prebuilt Node binaries, a wasm
bundle, an XCFramework, an AAR, wheels) is real, and it is phased in the
[roadmap](roadmap.md), not paid all at once.

---

## Where the trust lives

ton-net's value over an HTTP indexer is not "no middleman"; it is "verify the
answer." The trust guarantee is a two-part structure:

- **Block-sync** establishes a trusted masterchain block hash from a single pinned
  init key-block, by walking `getBlockProof` links and checking two-thirds
  validator signatures. This is the one trust assumption, and it is explicit in
  the API (`Sync.anchor`).
- **The proof engine** verifies every liteserver response against that trusted
  hash, through shard and account Merkle proofs, down to the representation hash of
  the returned state. Nothing on the read path is trusted to the liteserver.
- **The TVM** runs get-methods over what the proof engine has already verified, so
  a computed result is trustless too.

The API encodes the result: a `VerifiedAccount` and a `TvmResult` are different
types from a raw `ServerReportedResult`, so a consumer cannot mistake trust levels.

---

## Repository shape

The nirapod-labs multi-language monorepo pattern (as in signet), adapted to a Rust
core, and matching the matrix-rust-sdk layout.

```
ton-net/
  core/                  Rust workspace: the whole client stack
    tl/                    TL codec (tl-proto + TON schemas)
    crypto/                primitive wrappers
    adnl/                  channel, handshake, transports (TCP/UDP/WS)
    dht/                   Kademlia client
    liteserver/            liteServer.* query layer
    cell/                  cell/BoC, exotic cells, hashing
    proof/                 check_*_proof, block TL-B
    sync/                  key-block anchor + getBlockProof walk
    tvm/                   local get-method execution
    client/                the composed high-level Client
  bindings/
    node/                  napi-rs
    wasm/                  wasm-bindgen (WS transport)
    python/                pyo3 + maturin
    apple/                 UniFFI -> Swift package
    android/               UniFFI -> Kotlin/AAR
    flutter/               flutter_rust_bridge (optional)
  conformance/           canonical byte vectors + per-binding runners
  examples/              resolve-address, verified-account, run-get-method
  tools/                 vector generation against the reference node
  docs/                  adr/ · design/ · protocol/ · this file
```

Not every tree exists at once; the layout is the target and the
[roadmap](roadmap.md) is the order.

---

## What this is not

- Not a node. A client: it does not store the DHT, serve values, run consensus, or
  produce blocks. It consumes the two-thirds signatures, it does not cast them.
- Not RLDP, overlays, TON Storage, or TON Sites (NET-ADR-002). Client scope only.
- Not chain-agnostic. A dedicated TON library, TON-specific by design.
- Not a trust-me client. It verifies; a consumer that wants the unverified fast
  path must ask for the explicitly-unverified type.
