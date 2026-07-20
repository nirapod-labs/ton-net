# ton-net

The complete TON network client, written once in Rust and available in every
language.

> Working name. The launch name is an open decision (see
> [docs/roadmap.md](docs/roadmap.md)).

ton-net speaks TON's own protocols directly: TL, ADNL over TCP and UDP, the
Kademlia DHT, the liteserver query layer, Merkle-proof verification, key-block
sync, and a TVM for local execution. One correct implementation, exposed to
Node, browsers, Swift, Kotlin, Dart, and Python through thin bindings.

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

ton-net closes the gap for all of these at once. One permissively-licensed Rust
core, bound natively into each ecosystem, so a Rust service, a browser dapp, an
iOS wallet, an Android wallet, a Flutter app, and a Python script all talk to
TON the same correct way, without an intermediary.

---

## What it does

The full protocol surface a TON client needs, nothing node-only:

- **TL codec** with CRC32-IEEE constructor tags, boxed and bare types.
- **ADNL** over TCP (liteservers) and UDP (peer-to-peer), with channels.
- **DHT**, read and write: resolve an ADNL address to an IP, publish a record.
- **Liteserver queries**: account state, transactions, config, blocks, run a
  get-method, send a message.
- **Proof verification**: BoC and exotic-cell hashing, the TL-B for the block
  structures, and the `check_*_proof` routines, so a liteserver answer is
  verified rather than trusted.
- **Block sync**: a pinned key-block anchor, `getBlockProof` link-walking, and a
  two-thirds validator-signature check that anchors the current block.
- **TVM**: run a get-method locally against proven code and data, so a computed
  result is trustless, not server-reported.

Out of scope for v1.0.0 and deliberately so: RLDP, overlays, catchain, TON
Storage, and TON Sites. These are node-level or separate products. See
[NET-ADR-002](docs/adr/NET-ADR-002-scope.md).

---

## Design

The design is complete; code is phased. Read in order:

1. [NET-ADR-001](docs/adr/NET-ADR-001-architecture.md): one Rust core with
   per-language bindings, and why not one implementation per language.
2. [NET-ADR-002](docs/adr/NET-ADR-002-scope.md): the complete-client scope and
   what is deliberately left out.
3. [NET-ADR-003](docs/adr/NET-ADR-003-dependencies.md): the crate selection, and
   why the mature dependency lines.
4. [NET-ADR-004](docs/adr/NET-ADR-004-bindings-and-versioning.md): the binding
   toolchains, their order, and how versions are kept honest.
5. [NET-ADR-005](docs/adr/NET-ADR-005-tvm.md): the local TVM decision.
6. [System design](docs/design/system-design.md), [architecture](docs/architecture.md),
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
  against a validator-signature-anchored block, so the client trusts the server
  for nothing on the read path.

---

## Status

Design stage. Every wire fact in the design is drawn from primary sources: the
`ton_api.tl` and `lite_api.tl` schemas, the C++ reference in `ton-blockchain/ton`,
and the pytoniq light client. The CRC32 constructor-tag mechanism, the ADNL
handshake byte layouts, the DHT parameters, and the liteserver method set are
verified against the reference, not inferred.

---

## License

Apache-2.0 (permissive, unlike the C++ reference's LGPL), so any project, in any
language, can embed it without a copyleft obligation. See [LICENSE](LICENSE) and
[NOTICE](NOTICE).
