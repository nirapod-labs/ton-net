# Roadmap

From v0.1.0 to v1.0.0. Each version ends in something usable and depends on no
promise from a later one.

v1.0.0 is the whole surface a TON client speaks, plus the write path, across the
Rust core and the Node binding
([NET-ADR-008](adr/NET-ADR-008-scope-and-write-path.md)). What that surface is comes
from TON's own schemas rather than from any implementation of them.

Governing decisions: [NET-ADR-001](adr/NET-ADR-001-architecture.md),
[NET-ADR-003](adr/NET-ADR-003-dependencies.md),
[NET-ADR-006](adr/NET-ADR-006-trust-anchor.md),
[NET-ADR-007](adr/NET-ADR-007-signature-verification.md),
[NET-ADR-008](adr/NET-ADR-008-scope-and-write-path.md),
[NET-ADR-009](adr/NET-ADR-009-versioning-and-binding-sequence.md),
[NET-ADR-010](adr/NET-ADR-010-tvm-differential.md).

---

## Where this stands

Reading a proved account works end to end and is tested against mainnet. Sending a
transaction does not exist. Neither does the peer-to-peer half, the full type set,
or local execution. The releases below are the order they arrive in.

---

## Versioning discipline

Six axes, recorded in
[NET-ADR-009](adr/NET-ADR-009-versioning-and-binding-sequence.md). The short form:

- **Library version.** One SemVer number everywhere, mapped per registry. Breaking
  means an API break, a behavioural break (something that verified now fails, or
  something refused now passes), or a wire break. Pre-1.0, `0.MINOR` is breaking in
  every ecosystem, not only where Cargo enforces it.
- **Verification epoch.** A monotonic integer, independent of the library version,
  incremented whenever the proof engine's accept and reject boundary moves.
- **Support manifest.** The pinned schema revisions, the supported TVM
  `global_version` range, and the compiled capabilities, queryable at runtime and
  diffed against upstream in CI.
- **TVM global-version matrix.** A compatibility table, not a version number.
- **Registry mapping.** Generated, never hand-edited. PEP 440 and Maven stop being
  the identity at the first pre-release.
- **Toolchain floors and feature flags.** A minimum supported Rust version rises on
  a minor bump. Changing the default feature set is a major one.

---

## Release model

A milestone tag and a registry publish are two different acts. Every milestone
below is an annotated git tag when its gate passes.

| Milestone | git tag | registry |
|---|---|---|
| v0.1.0, v0.2.0 | yes | pre-release only (`-alpha`), not for production |
| v0.3.0 onward | yes | ordinary release |
| v1.0.0 | yes | ordinary release, API frozen |

v0.3.0 is the first ordinary release because a read is trust-minimized end to end
from there: the anchor comes from the config's pinned key block rather than from
anything a server offers.

---

## Binding sequence

The Rust core reaches parity carrying **only the Node binding**. v1.0.0 is the core
plus Node. Browser, Python, Swift and Kotlin ship afterwards.

Node earns its place: building it has already exposed two API holes the core's own
tests did not, an unconstructible `BlockIdExt` and a missing `verify_account` on
the facade. One consumer of the API is the cheapest design review available. Five
of them, before the API settles, multiply every core addition by five, and the
a core this size is not one that five binding surfaces can chase.

---

## Shipped

### v0.1.0: TL codec, ADNL over TCP, unverified liteserver reads, Node

The foundation. TL codec over `tl-proto` with the official schemas, the ADNL
handshake and stream framing, the liteserver query layer for reads, the config
loader, the napi-rs Node binding. Reads carry a `ServerReported` type because they
are not yet proof-verified.

### v0.2.0: Cell and BoC engine, proof engine

The cell model with exotic cells and level-mask representation hashing, BoC parse
and serialize, the TL-B for the block structures a proof walk needs, and the proof
routines. An account read verifies against a caller-supplied trusted block hash,
and a tampered proof is refused.

### v0.3.0: Block sync

The trust anchor. The init key block the config pins, `getBlockProof` link
walking, validator-set derivation from configuration parameters 28 and 34, and the
two-thirds signature check in both forms mainnet uses. A read is trust-minimized
end to end with only the pinned anchor taken on faith, and a proven head older than
the configured bound is refused rather than reported.

---

## The path to parity

Ordered by dependency first and value second.

### v0.4.0: Cell engine to full capability

The critical path, and nothing else can start ahead of it. Builders
and slices, the five dictionary variants, augmented dictionaries, prefix
dictionaries, usage trees, virtualization, lazy and large BoC handling, and Merkle
proof **creation** rather than verification alone.

The wallet, the full TL-B set and the TVM each depend on it.

*Gate:* a Merkle proof built by this crate verifies in the existing proof engine;
every dictionary variant round-trips against captured mainnet fixtures.

### v0.5.0: The write path

~4,500 lines, and the first milestone a wallet can use. External message
construction, `sendMessage` with confirmation waiting, transaction subscription,
and wallets v1 through v5R1, highload v2 and v3, lockup, seed phrases,
hierarchical derivation, and TON Connect proof verification.

The signer seam is the primary construction: a caller supplies a callback and the
library never sees key material. Whether any part of this creates custody is
settled before the code is written, and the seed and derivation support is the
part that has to be examined.

*Gate:* a transfer built, signed through the seam, sent to mainnet and observed in
a proven account read.

### v0.6.0: TL-B type set to parity

Every block, transaction, message, shard and configuration type, not
the subset a proof walk needs. The loader and serializer machinery, stack
serialization, augmented dictionary loaders.

*Gate:* a mainnet block decodes field for field against the reference node.

### v0.7.0: Liteserver API to parity, and a connection pool

The full method set, transaction proofs, out-message queue and
dispatch queue proofs, non-final block queries. The pool brings multiple
liteservers, sticky contexts, balancing, node exclusion, liveness pings and
failover, which is the operational gap a single connection leaves open.

*Gate:* every liteserver method answers against mainnet; the pool survives a
server dropping mid-query.

### v0.8.0: ADNL over UDP, and the DHT

Channel establishment over UDP, Kademlia with `findValue`,
`findNode`, `getSignedAddressList` and `store`, and signature verification on DHT
records.

*Gate:* a known validator's ADNL address resolves to a reachable endpoint through
the DHT, signature-verified.

### v0.9.0: RLDP, overlays, QUIC

The RaptorQ transfer layer, overlay membership and broadcast, and
the QUIC transport. Previously deferred past v1.0.0 and brought in by
[NET-ADR-008](adr/NET-ADR-008-scope-and-write-path.md).

*Gate:* an RLDP transfer completes against a real peer; an overlay is joined and a
broadcast received.

### v0.10.0: The TVM

~37,000 lines and the largest milestone by a wide margin. Decided in
[NET-ADR-010](adr/NET-ADR-010-tvm-differential.md).

The harness comes before the first opcode: CI builds a pinned C++ emulator, feeds
it a case, and compares. Opcodes land with their differential cases, never ahead of
them, and the corpus is captured from mainnet and re-derived against the emulator
rather than taken from elsewhere. BLS12-381 and secp256k1 come from `blst` and the
libsecp256k1 bindings rather than being hand-written. Each opcode declares its minimum
`global_version` and an inventory test asserts the table is complete.

Expect no user-visible progress until the harness runs. That is the correct shape
of this milestone.

*Gate:* the imported replay corpus reproduces against the C++ emulator;
get-methods for a corpus of real accounts match the reference node exactly, over
proven inputs.

### v0.11.0: Contract helpers and the HTTP fallback

NFT, jetton and TON DNS over the TVM, and a toncenter client for a
consumer that cannot reach a liteserver.

*Gate:* a jetton balance, an NFT's data and a DNS resolution all computed locally
over proven state.

### v1.0.0: Parity, API frozen

Every capability in NET-ADR-008 shipped. The API and the proof, sync and TVM
guarantees promised stable under SemVer. `VERIFY_EPOCH` and the
support manifest published as part of the frozen surface.

*Gate:* every capability NET-ADR-008 names is shipped and tested; the conformance
suite is green; the Node binding exercises all of it.

---

## After v1.0.0

- **The remaining bindings.** Browser (wasm-bindgen), Python (pyo3 and maturin),
  Swift and Kotlin (UniFFI). Additive, and they do not change the core.
- **Dart**, if Flutter becomes a real target.

---

## What could move v1.0.0

Stated honestly.

- **The TVM (v0.10.0).** Sixteen months of work in the reference implementation,
  still taking fixes, with an opcode test corpus twice the size of the opcode
  source. It is the largest single item and the most likely to consume the
  schedule, which is why it is sequenced late and why the harness comes first.
- **The cell engine (v0.4.0).** Everything depends on it, so an underestimate here
  moves every milestone after it.
- **Key handling on wallets (v0.5.0).** Seed and derivation support touches key
  material for the first time. A review outcome that constrains the design would
  reshape the release.
- **Scale.** What remains is several times what exists, and it is one maintainer's
  work. The order below is chosen so that each release is usable on its own rather
  than only as a step toward the last one.
