# ton-net

A TON network client written once in Rust, bound natively into other languages.

ton-net speaks TON's own protocols directly, with no HTTP indexer in the path.
Today that is TL, ADNL over TCP, the liteserver query layer, Merkle-proof
verification, and key-block sync: enough to read an account and prove it against
a block the client walked to itself, from Rust or from Node.

**It is early.** Measured against tonutils-go, the fullest client that exists,
ton-net covers **8 per cent** of the surface. Sending a transaction, wallets, the
DHT, RLDP, overlays and a TVM are all still ahead, and so are the browser,
Python, Swift and Kotlin bindings. What is here is finished and proven against
mainnet; there is simply not much of it yet. The
[roadmap](docs/roadmap.md) is the measured plan and
[NET-ADR-008](docs/adr/NET-ADR-008-parity-scope.md) is where the number comes
from.

---

## Why it exists

A full TON network client is a large piece of software: a TL codec, an encrypted
transport, a Kademlia DHT, the liteserver protocol, cell and proof verification,
validator-signature-checked block sync, and a TVM. Today that full stack exists
in exactly two community languages.

| Language | Full network client today |
|---|---|
| Go | tonutils-go |
| Python | pytoniq |
| C++ | the reference node (LGPL, not embeddable) |
| **Rust** | **nothing complete** |
| **TypeScript / JS** | liteserver-over-TCP only; no DHT, no UDP, no proofs |
| **Swift, Kotlin, Dart** | **nothing native; HTTP indexer or C++ FFI** |

Everyone else reaches TON through a centralized HTTP indexer (toncenter, tonapi)
or by binding the LGPL C++ `tonlib` over FFI. The first is a single point of
observation and failure; the second drags a heavy C++ build into every app.

ton-net exists to close that gap: one permissively-licensed Rust core, bound
natively into each ecosystem, so a Rust service, a browser dapp, an iOS wallet,
an Android wallet and a Python script eventually talk to TON the same correct
way, without an intermediary. Rust and Node are the two that work today; the
core reaches parity before the other bindings follow
([NET-ADR-009](docs/adr/NET-ADR-009-versioning-and-binding-sequence.md)).

---

## What it does

The whole client protocol surface. Working where unmarked; the rest carries the
release it lands in.

- **TL codec** with CRC32-IEEE constructor tags, boxed and bare types.
- **ADNL** over TCP (liteservers). UDP, peer-to-peer with channels, in v0.8.0.
- **DHT**, read and write: resolve an ADNL address to an IP, publish a record
  (v0.8.0).
- **Liteserver queries**: account state now; transactions, config, blocks, run a
  get-method and send a message across v0.5.0 to v0.7.0.
- **Proof verification**: BoC and exotic-cell hashing, the TL-B for the block
  structures, and the `check_*_proof` routines, so a liteserver answer is
  verified rather than trusted.
- **Block sync**: a pinned key-block anchor, `getBlockProof` link-walking, and a
  two-thirds validator-signature check that anchors the current block.
- **Cells at full capability**: builders, dictionaries, usage trees and Merkle
  proof creation, not parsing alone (v0.4.0).
- **The write path**: external messages, `sendMessage`, and wallets v1 through
  v5R1 behind a signer seam, so key material stays outside the library (v0.5.0).
- **RLDP, overlays and QUIC** (v0.9.0).
- **TVM**: run a get-method locally against proven code and data, so a computed
  result is trustless, not server-reported (v0.10.0). Until it lands a TON
  balance is a proven read and a jetton balance is not.

v1.0.0 is feature parity with tonutils-go at commit `749603a`, plus full wallet
support, across the Rust core and the Node binding. Parity is measured against
that pinned commit, because a target that ships weekly is not a gate that can
pass. See [NET-ADR-008](docs/adr/NET-ADR-008-parity-scope.md).

---

## Design

The design is complete; code is phased. Read in order:

1. [NET-ADR-001](docs/adr/NET-ADR-001-architecture.md): one Rust core with
   per-language bindings, and why not one implementation per language.
2. [NET-ADR-008](docs/adr/NET-ADR-008-parity-scope.md): the scope, measured
   against a pinned commit of the fullest client that exists.
3. [NET-ADR-003](docs/adr/NET-ADR-003-dependencies.md): the crate selection, and
   why the mature dependency lines.
4. [NET-ADR-009](docs/adr/NET-ADR-009-versioning-and-binding-sequence.md): one
   binding to v1.0.0, and versioning across six axes rather than one.
5. [NET-ADR-010](docs/adr/NET-ADR-010-tvm-differential.md): the TVM, its measured
   cost, and why the differential harness comes before the first opcode.
6. [NET-ADR-006](docs/adr/NET-ADR-006-trust-anchor.md) and
   [NET-ADR-007](docs/adr/NET-ADR-007-signature-verification.md): where trust
   starts, and how signatures are checked.
7. [System design](docs/design/system-design.md), [architecture](docs/architecture.md),
   [API design](docs/api-design.md), [conformance](docs/conformance.md),
   [protocol map](docs/protocol/wire-format.md), [roadmap](docs/roadmap.md).

The short version:

- **One core, in Rust.** The TON network stack is thick shared logic running on
  hostile bytes off the open internet. Reimplementing it per language is
  reimplementing the same adversarial-parsing and proof-verification risk per
  language. It is written and audited once.
- **Transport is a seam.** The core is sans-I/O over a transport trait: tokio UDP
  and TCP on native runtimes, WebSocket on the browser (which cannot open raw
  sockets). The same protocol logic runs everywhere; each runtime supplies the
  transport it can.
- **Proofs are not optional.** A complete client verifies what a liteserver
  returns. A response for an account carries Merkle proofs; ton-net checks them
  against a validator-signature-anchored block, so nothing the server says about
  the read is taken on its word.

---

## Status

Working, on mainnet, for the read path. A client connects to a liteserver over
ADNL, walks from the key block its config pins to the network's current head
checking a validator signature set at every link, and reads an account proved
against the block it arrived at. `v0.1.0` and `v0.2.0` are tagged.

What a first walk costs, measured against mainnet on 2026-07-22: 1246 links over
78 replies and a little over two minutes. Read it as a scale rather than a
constant, since the link count climbs with the chain. A client that saves the
block it ended on and hands it back next time pays one link instead, in about a
second.

Every wire fact is drawn from primary sources: the `ton_api.tl` and
`lite_api.tl` schemas, the C++ reference in `ton-blockchain/ton`, and the
pytoniq light client. The CRC32 constructor-tag mechanism, the ADNL handshake
byte layouts, the DHT parameters, and the liteserver method set are verified
against the reference, not inferred.

### What is still taken on trust

Two things, and they are the whole list. What an attacker controls at each
boundary the library crosses, and which check refuses it, is worked out in
[the threat model](docs/security/threat-model.md).

- **The block the config pins.** A walk has to start somewhere. It comes from
  the same file that decides which network the client is on, it is one visible
  block identity, and a caller who does not want to trust that file can pass
  their own starting block instead.
- **The local clock.** A proof establishes that a block is real and was
  committed by the validators, and says nothing at all about when it was handed
  over. A server replaying a genuine chain from last year passes every other
  check in the library. The clock is what catches it, so a client whose clock is
  wrong has a weaker freshness guarantee than one whose clock is right; the
  library reports a clock far enough behind rather than quietly passing.

---

## License

Apache-2.0. Copyright 2026 Nirapod Labs; maintained by athexweb3.

Permissive, unlike the C++ reference's LGPL, so any project, in any language, can
embed it without a copyleft obligation. See [LICENSE](LICENSE) and
[NOTICE](NOTICE).

Contributions are accepted under the same license, certified with a
[Developer Certificate of Origin](https://developercertificate.org/) sign-off.
See [CONTRIBUTING.md](CONTRIBUTING.md).
