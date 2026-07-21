# Roadmap

From v0.1.0 to v1.0.0. Each version ends in something usable and depends on no
promise from a later one. v1.0.0 is the complete client (NET-ADR-002): TL, ADNL
over TCP and UDP, DHT, liteserver, proof verification, block sync, and a TVM,
across the core plus the primary bindings.

Governing decisions: [NET-ADR-001](adr/NET-ADR-001-architecture.md) through
[NET-ADR-007](adr/NET-ADR-007-signature-verification.md).

---

## Versioning discipline

The library carries one version; the Rust crates move in lockstep
(cargo-release `shared-version`). Each published language package carries its own
registry-appropriate version, mapped to the library version in a table
(NET-ADR-004).

SemVer is measured against the observable API and the wire behavior. A wire or
proof-verification change is breaking; an internal refactor is not. The library
stays `0.x` until the API and the proof, sync, and TVM guarantees are stable
enough to promise. **v1.0.0 is that deliberate line**, not a marketing number.
libsignal, a comparable wire library, is still `0.x` after years; ton-net reaches
`1.0` only when completeness and stability are both real.

---

## Release model

A milestone tag and a registry publish are two different acts (NET-ADR-004). Every
milestone below is recorded as a git tag when its gate passes. Registry publishing
is gated separately, on the trust boundary:

| Milestone | git tag | registry (crates.io, npm, ...) |
|---|---|---|
| v0.1.0, v0.2.0 | yes | pre-release only (`-alpha`), not for production |
| v0.3.0 through v0.9.0 | yes | ordinary release |
| v1.0.0 | yes | ordinary release, API frozen |

The reason is honesty at the version-string level. A read is trust-minimized end
to end only once block sync anchors it at v0.3.0. Before that, a read is the
server's unproven word: the API marks it with a `ServerReported` type so it cannot
be mistaken for verified state in code, and the registry channel is the matching
signal at the version level. v0.3.0 is therefore the first ordinary registry
release; v0.1.0 and v0.2.0 reach a registry, if at all, only as marked
pre-releases.

---

## The path

Each milestone lists what ships, which layer it exercises, and its exit gate.

### v0.1.0: TL codec + ADNL-TCP + liteserver reads (unverified) + Node

The foundation and the first useful slice. TL codec over `tl-proto` with the
official schemas; the ADNL-over-TCP handshake and stream framing; the liteserver
query layer for reads; the config loader; the napi-rs Node binding.

Reads are **not proof-verified yet** and are marked so in the API with a
`ServerReported` type. This already does something no TypeScript library does
today: talk to a liteserver directly from Node over ADNL, no HTTP indexer.
Published, if at all, only as a pre-release (`-alpha`), not for production,
because a read here is still the server's unproven word.

*Gate:* from Node, connect to a mainnet liteserver, call `getMasterchainInfo` and
`getAccountState`, and get well-formed decoded results. The async-across-FFI
design is proven on the easiest binding. Full plan:
[docs/plan/v0.1.0.md](plan/v0.1.0.md).

### v0.2.0: Cell/BoC engine + proof engine

The trust-minimization core. The cell model with exotic cells and level-mask
representation hashing; BoC parse and serialize; the TL-B for the block
structures; the five `check_*_proof` routines.

*Gate:* an account read is verified against a **caller-supplied trusted block
hash** (sync comes next); a tampered proof is rejected; results match the
reference node for a corpus of real accounts. Still a pre-release (`-alpha`):
verification here needs a caller-supplied hash, so a read is not yet
trust-minimized end to end.

### v0.3.0: Block-sync engine

The trust anchor. The init key-block the network config pins, `getBlockProof`
link-walking, validator-set derivation from config 34, and the two-thirds Ed25519
signature check in both of the forms mainnet uses. After this, `getAccount` is
trust-minimized end to end with no caller-supplied hash.

Decisions in [NET-ADR-006](adr/NET-ADR-006-trust-anchor.md) and
[NET-ADR-007](adr/NET-ADR-007-signature-verification.md); plan in
[docs/plan/v0.3.0.md](plan/v0.3.0.md).

*Gate:* sync from the pinned init key-block to the current masterchain head across
at least one validator-set rotation, matched against the reference node's proof
for the same range. A full proven read needs nothing trusted but the anchor. This
is the **first ordinary registry release** (NET-ADR-004): a read is now
trust-minimized with only the pinned anchor.

### v0.4.0: Browser (wasm) binding

wasm-bindgen plus the `WsTransport`, honest about its limits: liteserver-only,
through a WebSocket-to-liteserver proxy, no DHT, no UDP. Done here, second among
bindings, so the browser's no-threads and no-socket constraints harden the
sans-I/O core before the mobile bindings lock the API.

*Gate:* a web page opens a liteserver channel through a proxy, reads and
proof-verifies an account. The transport seam holds under browser constraints.

### v0.5.0: ADNL-UDP + DHT (read and write)

The peer-to-peer branch. ADNL-over-UDP with channels; the Kademlia DHT with
`findValue`, `findNode`, `getSignedAddressList` and `store`; signature
verification on DHT records. This unblocks address resolution, TON DNS groundwork,
and peer discovery, and it is what a validator-geography or explorer tool needs.

*Gate:* resolve a known validator's ADNL address to a reachable IP through the
DHT, signature-verified, matched against a known-good client.

### v0.6.0: Python binding

pyo3 plus maturin; wheels per platform. Server, CLI, and test surface, and a
second independent binding that exercises the API shape beyond Node and wasm.

*Gate:* the Python package resolves an address and proof-verifies an account,
published as a wheel.

### v0.7.0: TVM (local get-method execution)

The last trust hole (NET-ADR-005). Adapt a validated Rust TVM if one passes the
conformance gate; otherwise begin the C++-semantics port. Get-methods run locally
over proven code, data and config, returned as a trust-minimized result distinct
from a raw server response.

This is the **highest-uncertainty milestone**: if no existing Rust TVM reproduces
mainnet semantics exactly, the fallback port is a major effort and this milestone
(and v1.0.0) moves out accordingly. It is sequenced late so everything else ships
without waiting on it.

*Gate:* get-methods for a corpus of real accounts (wallet `seqno`,
`get_public_key`; jetton `get_wallet_data`; DNS resolution; common contracts)
reproduce reference-node results exactly, over proven inputs.

### v0.8.0: Swift + Kotlin (UniFFI)

One crate, both mobile bindings: XCFramework via Swift Package Manager, AAR via
Maven. Done after the API has stabilized through five prior bindings, because the
mobile artifact matrix is the heaviest CI loop. This is the reach that makes
ton-net the first native TON client on iOS and Android without an HTTP indexer or
C++ FFI.

*Gate:* a Swift test and a Kotlin build proof-verify an account on-device (or
simulator/emulator in CI).

### v0.9.0: Hardening, conformance, docs

The whole conformance vector set wired into every binding's CI; the TL fuzz target
and an adversarial-peer harness; the block-sync and proof paths under negative
tests; complete API docs and examples per language. No new protocol surface, only
the evidence that what exists is correct.

*Gate:* every binding reproduces the conformance vectors in CI; the fuzz target
runs clean; the negative-test suite (tampered proofs, forged records, hostile
packets) passes.

### v1.0.0: The complete client, API frozen

Everything above, stable: TL, ADNL TCP and UDP, DHT read and write, liteserver,
proof verification, block sync, and the TVM, across the Rust core plus Node,
browser, Python, Swift and Kotlin. The API and the proof, sync and TVM guarantees
are promised stable under SemVer.

*Gate:* the completeness bar of NET-ADR-002 is met and verified; the API is frozen;
the conformance suite is green across all shipped bindings.

### Dart (flutter_rust_bridge): optional, alongside or after 1.0

Built only if Flutter is a real target (NET-ADR-004). Capable but on a beta
channel, and every consuming app compiles the Rust, so it is not gated into 1.0.

### Post-1.0: the node line (v2 candidate)

RLDP, overlays, and full-node block exchange, behind a clear capability boundary,
if real demand appears (NET-ADR-002). The transport and TL layers already serve
them; this is additive, not a rework.

---

## Binding order, in one place

Node → browser → Python → Swift+Kotlin → (Dart optional). Node first for the best
async story and cheapest iteration; browser second so its hard constraints shape
the core early; mobile after the API stabilizes because its CI is heaviest.
Rationale in [NET-ADR-004](adr/NET-ADR-004-bindings-and-versioning.md).

---

## What could move v1.0.0

Stated honestly:

- **The TVM (v0.7.0).** If no existing Rust TVM passes the conformance gate, the
  fallback port is the largest single effort in the project. This is the main
  schedule risk, sequenced late for exactly that reason.
- **Proof-engine level-mask and validator-set correctness.** The pytoniq reference
  has documented gaps here; getting them exactly right (not copied) is subtle work
  on the critical trust path. Level-mask hashing was settled in v0.2.0 against a
  mainnet root match, and the validator-set derivation in v0.3.0 against 107475 real
  signatures, so this risk is now largely spent.
- **Mobile CI.** The XCFramework and AAR multi-architecture build is the heaviest
  pipeline and the most likely to consume time in v0.8.0.
