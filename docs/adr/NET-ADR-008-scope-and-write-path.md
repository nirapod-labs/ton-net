---
id: NET-ADR-008
title: Scope v1.0.0 as the whole client protocol surface, plus the write path
status: accepted
date: 2026-07-22
supersedes: NET-ADR-002
superseded-by: none
---

# NET-ADR-008: Scope v1.0.0 as the whole client protocol surface, plus the write path

## Context

NET-ADR-002 scoped v1.0.0 as a complete client and put RLDP, overlays and the
node-adjacent protocols outside it. Two things in that record did not hold up.

The first is the exclusion itself. RLDP and overlays are client protocols: a client
uses them to fetch large objects and to join a broadcast group, and neither
requires running a node. The line NET-ADR-002 drew separated protocols by how
node-flavoured they sounded rather than by whether a client needs them.

The second is larger. `sendMessage` appears in NET-ADR-002's own in-scope list and
in no release of the roadmap, and no send path exists in the tree. The library is
read-only. A client that cannot submit an external message cannot back a wallet,
which is the thing this library exists to be used by, and no amount of read
verification substitutes for it.

## Decision

Scope v1.0.0 as the whole surface a TON client speaks, plus the write path, across
the Rust core and the Node binding.

The authority for what that surface is is TON's own schemas, `ton_api.tl`,
`lite_api.tl` and `block.tlb`, rather than any implementation of them. In scope:

1. **TL codec.** CRC32-IEEE constructor tags, boxed and bare.
2. **ADNL** over TCP and UDP, with channels.
3. **DHT.** Kademlia, read and write, with signature verification on records.
4. **RLDP**, including the RaptorQ transfer layer.
5. **Overlays.** Membership and broadcast.
6. **QUIC transport.**
7. **Liteserver query layer.** The client method set, including `sendMessage`, with
   a connection pool over several servers: sticky contexts, balancing, node
   exclusion, liveness pings and failover.
8. **Cell engine at full capability.** Builders, slices, the dictionary variants,
   augmented dictionaries, usage trees, virtualization, and Merkle proof
   *creation* rather than verification alone.
9. **The full TL-B type set**, not the subset a proof walk needs.
10. **Proof engine and block sync**, as they already exist.
11. **The write path.** External message construction, `sendMessage` with
    confirmation waiting, transaction subscription, and wallets v1 through v5R1,
    highload v2 and v3, lockup, seed phrases, hierarchical derivation, and TON
    Connect proof verification.
12. **A local TVM**, so a get-method result is computed over proven state rather
    than taken from a server.
13. **Contract helpers**: NFT, jetton and TON DNS.
14. **An HTTP fallback client**, for a consumer that cannot reach a liteserver.

Out of scope and staying out: catchain and validator session, full-node block
exchange, TON Storage, TON Sites, and block production. Those are what a validator
or a node does, not what a client does.

What does not change is the trust posture, which is the reason this library exists
rather than a translation of one that already does. These are invariants:

- The anchor comes from the network config's pinned key block and is never taken
  from what a server offers first (NET-ADR-006).
- `Verified<T>` has a private constructor and cannot be forged; `ServerReported<T>`
  is a different type. A caller cannot confuse them.
- A proven head older than the configured bound is refused rather than reported.
- `VERIFY_EPOCH` moves when the accept and reject boundary moves (NET-ADR-009).
- The crates that decode bytes from an unvouched peer deny `unwrap`, `panic`,
  `unreachable` and slice indexing.

## Alternatives considered

- **Keep NET-ADR-002 unchanged.** Rejected. It excludes client protocols on a
  distinction that does not survive inspection, and it omits the write path while
  listing `sendMessage` in scope.
- **Narrow v1.0.0 to trust-minimized read and send**, deferring the TVM and the
  peer-to-peer protocols. Considered seriously and declined: it would ship in
  months rather than years, at the cost of leaving get-method results server-
  trusted, which is the largest remaining hole in an otherwise verified client.
- **Ship the write path as a separate crate.** Rejected. The wallet needs the cell
  builders and the message TL-B that the read path already half carries, and
  splitting them would duplicate both.

## Consequences

- The work is several times what exists today, and the TVM alone is the largest
  single component in it. The roadmap sequences accordingly and says plainly what
  could move v1.0.0.
- The binding plan does not survive this scope unchanged, because every core
  addition crosses each binding surface. NET-ADR-009 takes the core to
  completeness carrying Node alone.
- The TVM's approach is settled separately in NET-ADR-010.
- Wallet support puts key material in the library's reach for the first time, and
  whether any of it creates custody is settled before that code is written. The
  signer seam, where a caller supplies a callback and the library never sees a key,
  is the primary construction.
- The cell engine becomes the critical path. The wallet, the full TL-B set and the
  TVM each depend on capabilities it does not have yet, so nothing else starts
  first.
- Releases run past v0.9.0, so the roadmap uses two-digit minors.

## Chain scope

TON-specific (see NET-ADR-001).

## Custody and security

The library holds no user keys today. Wallet support changes what is possible, not
what is decided: the signer seam is the primary construction, so a caller supplies
a callback and the library never sees key material. Seed phrase and derivation
support does touch key material and is the part that has to be examined before it
is written.

## Verification

- Each release names the capabilities it brings in and the gate that proves them.
- The five trust invariants are covered by tests that fail if a default moves: the
  anchor test refuses a server-offered head, the freshness test refuses a stale
  proven head, `Verified<T>` cannot be constructed outside the crate, and the epoch
  transcript fails if what verifies changes.
