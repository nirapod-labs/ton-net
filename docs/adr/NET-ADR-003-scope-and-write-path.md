---
id: NET-ADR-003
title: Client scope, and the write path
status: accepted
date: 2026-07-23
supersedes: none
superseded-by: none
---

# NET-ADR-003: Client scope, and the write path

## Context

NET-ADR-001 fixes what ton-net is for, and NET-ADR-002 fixes the architecture that carries
it: one audited core, a sans-I/O transport seam, and thin per-language bindings. What neither
settles at the level of a list is the surface a client speaks, the exact set of protocols and
capabilities that are in and the set that is out. Without that list a scope question was
answered by whether some consumer wanted the capability, the sort NET-ADR-001 rejected, and it
was re-answered each time it came up.

This record fixes the surface. It states the whole of what a TON client speaks, the write path
within that surface, and the invariant trust properties every part of the surface is built
under. The authority for the surface is TON's own schemas, the TL types, the TL-B definitions,
the block and proof formats, and the ADNL and liteserver protocols, not any implementation. A
client conforms to the network's definitions rather than to another program's reading of them.

## Decision

**1. Scope is the whole surface a program talking to TON speaks, and never what a node or a
validator does.** Growth means a more complete and more widely adopted client (NET-ADR-001),
not a move toward network infrastructure.

In scope:

- The TL codec.
- ADNL over TCP and over UDP with channels.
- DHT read and write, with record signature verification.
- RLDP.
- Overlays.
- QUIC.
- The liteserver query layer, including sendMessage over a connection pool.
- The cell engine at full capability: builders, slices, the dictionary variants, augmented
  dictionaries, usage trees, virtualization, and Merkle proof creation.
- The full TL-B type set.
- The proof engine and block sync.
- The write path: external message construction, sendMessage with confirmation, transaction
  subscription, the wallet contract families, seed phrases, hierarchical derivation, and TON
  Connect proof verification.
- A local TVM.
- Contract helpers.
- An HTTP fallback client.

Out of scope, and staying out:

- Catchain and the validator session.
- Full-node block exchange as a participant.
- TON Storage.
- TON Sites.
- Block production.

Those are what a validator or a node does. A client consumes the network and verifies it. It
reads DHT records and publishes its own, and it never serves values to other peers, hosts
storage or sites, exchanges full blocks as a participant, runs consensus, or produces blocks.
The out-of-scope list is a boundary, not a backlog: the items on it are declined, not deferred.

**2. The write path is in scope, and it is the floor.** NET-ADR-001 fixes a trust-minimized
read-and-send client, able to back a wallet end to end, as the floor the project holds itself
to. The write path is that send half: it constructs an external message, sends it with
confirmation, and can follow a transaction to its result. Its first contact with key material
is a signer seam, where the caller supplies the signing operation and the library never sees a
private key or a seed. The custody section states what that does and does not settle.

**3. Every part of the surface, present and future, is built under five invariant trust
properties.** A part that cannot be built under them is escalated rather than shipped
(NET-ADR-001, the consumer-priority guard).

- The trust anchor comes from the config's pinned key block and is never taken from a server
  first. A server's head is a target to ask for, and every block on the way to it is proved.
- A verified value has a private constructor and is a distinct type from a server-reported
  value. There is no operation that turns the second into the first.
- A proven head older than a configured bound is refused. A proof says a block is real, not
  when it was served, so the local clock is the only freshness signal and a stale head is a
  named failure.
- The verification epoch moves when the accept and reject boundary moves, and only then. It is
  a separate number from the API version, because what the library accepts as proven can change
  while the API does not, and the reverse.
- Every crate that decodes bytes from a peer denies unwrap, expect, panic, unreachable, todo,
  and slice indexing, and forbids unsafe code. A decoder that unwinds on hostile input is a
  denial of service in whatever embeds it.

## Alternatives considered

- **Bound the surface by the wallet's needs.** Rejected. The wallet is a soft consumer and the
  surface is not bounded by one caller (NET-ADR-001).
- **Sort each capability in or out by whether a consumer asks for it.** Rejected. That is the
  drift NET-ADR-001 named, and it is what left the node and indexer scale operations wrongly
  deferred.
- **Grow toward node or validator capability**, serving DHT values to other peers, exchanging
  full blocks as a participant, or producing blocks. Rejected. That crosses the boundary the
  purpose fixes. Reading and publishing a client's own DHT records stays a client action;
  answering other peers as infrastructure does not.
- **Defer the write path behind a read-only 1.0.** Rejected in NET-ADR-001 and reaffirmed here:
  the write path is the floor, not a later addition.
- **Ship the HTTP fallback as a verified path by trusting an indexer.** Rejected. A transport
  that cannot carry a proof returns a server-reported value, never a verified one. The type
  discipline holds regardless of transport.

## Consequences

- A scope question resolves against the list above rather than being re-argued.
- The current build is a subset of this surface: the TL codec, ADNL over TCP, the liteserver
  read layer (masterchain info, account state, and block proof), the cell engine that the
  current milestone is bringing to full capability, the proof engine and block sync that back
  the verified read, the verified read facade, and the Node binding. The rest of the surface is
  committed scope, sequenced dependency-first (NET-ADR-001), with the product spine, the cell
  engine then the write path, ahead of the rest.
- Each new part of the surface inherits the five invariants as part of its definition of done.
  A part that cannot meet them is escalated under the consumer-priority guard, not shipped
  around them.
- The HTTP fallback and any other non-proving transport surface their results as
  server-reported values, so adding a transport never weakens a verified read.
- The out-of-scope boundary is a standing answer. A request to serve peers, host storage or
  sites, or produce blocks is declined by this record.

## Chain scope

TON-specific (NET-ADR-001, NET-ADR-002). The surface fixed here is TON's own: the TL codec,
TL-B, ADNL, the liteserver protocol, the DHT, RLDP and overlay stack, and the TVM. Composing
several chains lives above ton-net, in the consumer.

## Custody and security

No user keys today. The write path is where key material first enters the picture, and it
enters through a signer seam: the caller supplies the signing operation, and the library never
holds or sees a private key or a seed. Constructing and broadcasting an external message is not
custody. Signing with a key the library holds would be, and the library does not do that. This
is the non-custodial line, and it is the reason the write path can be in scope without the
library taking control of user funds.

The seed-phrase standard and the hierarchical derivation scheme are in scope as capabilities,
and they are security-relevant facts. This record does not fix which mnemonic standard or which
derivation scheme they use. Those are settled in a security review before that code is written,
and nothing here should be read as choosing one. TON Connect proof verification is a
verification capability rather than a signing one: it checks a proof a wallet produced and holds
no key. The custody position of NET-ADR-001 is unchanged by this record; this record fixes that
the write path is in scope and that its key contact is the signer seam.

## Verification

Each invariant is checkable against named code in the current build.

- Anchor from the config, never a server first: `crates/ton-net/src/config.rs` reads the anchor
  from the config's `validator.init_block` and names it the only input a verified read trusts
  from the chain's side; `crates/ton-net/src/client.rs` starts the walk from that block or a
  caller-supplied anchor and uses the server's head only as a target the walk is required to
  reach; `crates/ton-net/src/lib.rs` and `crates/ton-net/src/verified.rs` state the same in the
  read's own documentation.
- A private constructor and a distinct type: `crates/ton-net/src/verified.rs` gives
  `Verified<T>` a crate-private constructor and no public one, and it is a different type from
  `ServerReported`; `crates/ton-net/src/lib.rs` states there is no way to turn one into the
  other.
- A stale head refused: `crates/ton-net/src/sync.rs` returns a stale error for a proven head
  older than the bound, and returns a clock error rather than silently passing when the local
  clock is far behind; `crates/ton-net/src/config.rs` carries the default bound and the setter.
- The verification epoch: `crates/ton-net/src/lib.rs` defines the epoch and the rule for when it
  moves, separate from the API version.
- The decode lints: the identical deny block and the unsafe-code forbid sit at the top of
  `crates/ton-net-tl/src/lib.rs`, `crates/ton-net-cell/src/lib.rs`,
  `crates/ton-net-block/src/lib.rs`, `crates/ton-net-adnl/src/lib.rs`,
  `crates/ton-net-lite/src/lib.rs`, and `crates/ton-net/src/lib.rs`.

The out-of-scope boundary is observable as an absence: no crate serves DHT values to other
peers, exchanges full blocks as a participant, or produces blocks. The write path's floor is
observable when it is built, as a real transfer sent and then read back in a proven account read
(NET-ADR-001).
