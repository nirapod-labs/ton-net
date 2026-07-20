---
id: NET-ADR-002
title: Scope is a complete TON client, node-only protocols excluded
status: proposed
date: 2026-07-20
supersedes: none
superseded-by: none
---

# NET-ADR-002: Scope is a complete TON client, node-only protocols excluded

## Context

"ton-net" names the whole TON network layer, and the goal is to be the reference
client library. So the scope must be complete enough to earn the name, and bounded
so it is a client library and not a half-built node.

TON's network protocols split cleanly by who runs them. Primary-source analysis
(the `ton_api.tl` and `lite_api.tl` schemas, the C++ reference, tonutils-go and
pytoniq) shows two groups:

- **Client protocols**: what a program talks-to-TON needs. TL; ADNL over TCP (to
  liteservers) and UDP (peer and DHT); the DHT itself; the liteserver query set;
  cell, BoC and Merkle-proof verification; validator-signature block sync; and a
  TVM to execute get-methods locally. tonutils-go and pytoniq implement this group
  (pytoniq minus RLDP), and it is what wallets, explorers, indexers, and tooling
  actually consume.
- **Node protocols**: RLDP (reliable large transfer), overlays (per-shard gossip
  subnets), catchain and validator-session (BFT consensus), full-node block
  exchange, plus node infrastructure (`engine.*`, `db.*`). A client consumes the
  *output* of consensus (the two-thirds block signatures it verifies) but never
  participates. These exist to run a node or to serve TON Sites and TON Storage.

A complete *client* is the first group. Including the second would roughly double
the surface for protocols almost no client uses, and would make ton-net a node
project rather than a client library.

## Decision

Scope ton-net v1.0.0 as a **complete TON client**: every client protocol, nothing
node-only.

In scope for v1.0.0:

1. **TL codec**: CRC32-IEEE constructor tags, boxed and bare, bytes and vector.
2. **ADNL**: over TCP (liteserver transport) and UDP (peer-to-peer), including
   channel establishment.
3. **DHT**: read (`findValue`, `findNode`, `getSignedAddressList`) and write
   (`store` a signed address record), Kademlia with k=10, a=3.
4. **Liteserver query layer**: the client method set (account state,
   transactions, config, blocks, `runSmcMethod`, `sendMessage`, block proofs).
5. **Proof engine**: BoC and exotic-cell hashing (pruned branch, Merkle proof,
   Merkle update, with level masks), the TL-B for Block, ShardState,
   ShardAccounts, Account, Transaction and ConfigParams, and the five
   `check_*_proof` routines.
6. **Block-sync engine**: a pinned init key-block anchor, `getBlockProof`
   link-walking, validator-set derivation (config params 28 and 34), and the
   two-thirds Ed25519 signature check over `ton.blockId`.
7. **TVM**: a Rust TVM (adapt or embed, decided in NET-ADR-005) to run
   get-methods locally against proven code and data, so a computed result is
   trustless rather than server-reported.
8. **Config loader**: `global-config.json` to liteserver list, DHT seed nodes,
   and init block.

Out of scope for v1.0.0, deferred to a post-1.0 node-capabilities line: **RLDP,
overlays, catchain and validator-session, full-node block exchange, TON Storage,
TON Sites (RLDP-HTTP), and node infrastructure**. These are node-level or
separate products, confirmed by the namespace census of `ton_api.tl` (engine 131,
storage 92, tonNode 82, overlay 58, consensus 51 constructors).

## Alternatives considered

- **Node-complete (add RLDP and overlays).** Rejected for v1.0.0. It roughly
  doubles the surface for protocols a client does not use; TON Sites is largely
  dormant; and it turns a client library into a node. Kept as a possible post-1.0
  line (v2) if real demand appears, behind a clear capability boundary.
- **Liteserver-only, no DHT, no UDP.** Rejected. A wallet alone could live without
  DHT, but the goal is the reference *client* library, and DHT address resolution,
  TON DNS, and peer discovery are things real consumers need. Excluding them would
  make ton-net incomplete against tonutils-go and pytoniq.
- **Defer the TVM past 1.0.** Rejected under the completeness bar. Without a local
  TVM, `runSmcMethod` results are server-trusted, which is a hole in an otherwise
  proof-verified client. A complete client closes it. NET-ADR-005 decides how.
- **Unverified client (skip proofs).** Rejected. A client that does not verify
  liteserver proofs only relocates trust to the liteserver. Proof verification is
  part of what "complete" means, not an add-on.

## Consequences

- ton-net at v1.0.0 matches or exceeds the community's fullest clients
  (tonutils-go, pytoniq) in one Rust core across six languages, which is the
  reputation bar it is built to clear.
- The proof engine, block-sync, and TVM are the hard, high-value original work; no
  Rust code implements them. They are the main engineering cost and the main
  differentiator.
- Excluding node protocols keeps the surface a maintainable one-person-plus effort
  and keeps the library embeddable (a node stack would not be).
- The schema files (`ton_api.tl`, `lite_api.tl`, `block.tlb`) are pinned inputs;
  drift against the reference node is a real risk, covered by conformance.
- A post-1.0 node line (RLDP, overlays) remains open without reworking the core,
  because the transport and TL layers already serve it.

## Chain scope

TON-specific by nature (see NET-ADR-001). A standalone TON library, not a
chain-agnostic core.

## Custody and security

Custody gate: **pass, structurally** (NET-ADR-001). No user keys, ever.

Two properties are load-bearing and first-class:

1. **Proof verification is a correctness requirement, not a feature flag.** A bug
   that accepts an invalid Merkle proof, or checks level-0 cell hashes where a
   level mask requires otherwise, silently defeats the trust guarantee. The
   pytoniq reference has documented gaps here (validator-set shuffle, level-mask
   handling); ton-net implements them correctly rather than copying.
2. **The block-sync trust anchor is a single, minimized, documented assumption.**
   The pinned init key-block must be obtained correctly out-of-band; everything
   after it is cryptographic. The API makes the anchor explicit, never hidden.

## Verification

- An account read returns state whose representation hash matches the proven
  account hash, anchored through shard and block proofs to a masterchain block
  whose signatures verify at two-thirds validator weight against the pinned init
  key-block.
- A tampered proof (one flipped byte in the Merkle proof BoC) is rejected.
- A get-method executed through the TVM against proven code and data returns the
  same result as the reference node, and the API distinguishes a TVM-executed
  result from a raw `runSmcMethod` server response.
- A `getBlockProof` walk across a validator-set rotation transfers trust correctly,
  checked against the reference node's proof for the same range.
