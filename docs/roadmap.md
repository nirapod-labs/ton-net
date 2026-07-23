<!--
SPDX-License-Identifier: Apache-2.0
SPDX-FileCopyrightText: 2026 Nirapod Labs
-->

# ton-net roadmap

This is the release sequence from where ton-net stands today to v1.0.0. It records
the order the client surface arrives in and the bar each step clears, so scope and
sequence are read from one place rather than re-argued per change.

The surface itself is fixed in [NET-ADR-003]: the whole of what a program talking to
TON speaks, and never what a node or a validator does. The order is dependency-first
([NET-ADR-001]), which places the write path early and the local TVM last among the
large components. The product spine, the cell engine then the write path, is the
highest-priority thread and runs without interruption, because it is what a dependent
wallet needs first. There is no external deadline: completeness is preferred over an
early version label. v1.0.0 is full parity, including the TVM, and the API freezes
only when the client is genuinely complete.

## How releases are numbered

[NET-ADR-008] fixes the versioning. Every crate carries one SemVer version through
workspace inheritance and moves in lockstep, there is one changelog for the library,
and release-plz owns the bump, the tag, and the publish. SemVer is measured against
the observable API and the wire behavior, so a proof-verification change is breaking
and an internal refactor is not.

The version today is 0.3.0, the first published release. v0.1.0 and v0.2.0 are git
tags that were never published. Before 1.0.0 every minor release can break in every
ecosystem this ships to, so a consumer pins to a minor and upgrades on purpose. The
milestone numbers below are the build order; the published version stays on the 0.x
line until the freeze at 1.0.0.

One number runs beside the version. `VERIFY_EPOCH`, 1 today, rises only when the set
of things the library accepts as proven changes. A caller that stored the epoch a
result was verified under re-checks when the current value is higher. Each rise is
recorded in [the changelog] as the delta in what is now accepted and what is now
refused.

## Where the code stands today

v0.3.0 is a trust-minimized read path: connect, sync, and read a proven account.
Against a liteserver it speaks TON's own protocols and verifies every answer against
validator signatures rather than trusting the server that sent them.

Working today:

- The TL codec (`ton-net-tl`), ADNL over TCP (`ton-net-adnl`), and the liteserver
  read layer (`ton-net-lite`): masterchain info, account state, and block proof.
- The cell model and bag-of-cells codec (`ton-net-cell`): parsing, building,
  representation hashing, exotic cells and level masks, the dictionary, and Merkle
  proof verification.
- The block structures and the proof engine (`ton-net-block`), and block sync in the
  `ton-net` facade: a walk from the key block the config pins to the network's head,
  checking that more than two-thirds of the validator set has signed at every link
  ([NET-ADR-005], [NET-ADR-006]).
- The verified-read facade. `Client::account` returns `Verified<Account>`, a type
  with a private constructor that cannot be built outside the crate without a proof
  having checked out. `account_reported` is the unchecked exception and returns a
  different type. `connect_from` and `anchor` turn a first cold walk into a single
  link on the next run.
- The Node binding (`bindings/node`), the first of the planned bindings.

Two inputs stay trusted, and both are named: the block the config pins, and the local
clock. A proof says a block is real, not when it was served, so a proven head older
than a configured bound is refused ([NET-ADR-005]).

Not built yet, all of it committed scope: the write path and wallets, the full TL-B
type set, the full liteserver method set and a connection pool, ADNL over UDP and the
DHT, RLDP, overlays and QUIC, the local TVM, contract helpers, and an HTTP fallback
([NET-ADR-003]). The in-flight work on top of v0.3.0 is the cell engine's final
capability, which is Milestone 1.

## Standing gates

Every milestone clears the same floor before it is done, so each entry below names
only the check it adds.

- The five invariant trust properties of [NET-ADR-003]: the anchor comes from the
  pinned key block and never from a server first; a verified value has a private
  constructor and is a distinct type from a server-reported one, with no operation
  that turns one into the other; a proven head older than the configured bound is
  refused; the verification epoch moves when the accept and reject boundary moves and
  only then; and every crate that decodes bytes from a peer denies unwrap, expect,
  panic, unreachable, todo, and slice indexing, and forbids unsafe code.
- Performance within the safety floor ([NET-ADR-001]). Correctness and safety are the
  floor and win any real conflict, and a capability that is correct and safe but
  needlessly slow is not finished.
- Node-scale breadth as isolated paths. The extra reach a demanding consumer needs is
  carried as feature-gated or child paths that cost a lighter consumer nothing at
  runtime ([NET-ADR-009]). A capability that cannot be built this way, without
  degrading the immutable cell type, the mobile binary size, or the simple
  read-and-build API, is escalated rather than taken automatically ([NET-ADR-001]).

## The sequence

At a glance:

1. The cell engine to full capability (current).
2. The write path and wallets.
3. The full TL-B type set.
4. The liteserver method set and a connection pool.
5. ADNL over UDP and the DHT.
6. RLDP, overlays, and QUIC.
7. The local TVM.
8. Contract helpers and an HTTP fallback.
9. v1.0.0: full parity, the API frozen.

### Milestone 1: The cell engine to full capability

Status: in flight on top of v0.3.0.

Delivers: the cell model at full capability, so a consumer can build and read any TON
structure and a wallet can build the cells a message needs. The pieces [NET-ADR-003]
names are in the tree: builders and slices, the dictionary variants including the
augmented and prefix dictionaries, usage trees, virtualization, and Merkle proof
creation.

Depends on: nothing above it. This is the base every later milestone reads.

Gate: every gate green. The property tests over the cell codec hold: a bag-of-cells
round trip preserves a cell's representation hash and its bytes, a parsed cell hashes
to what its parts imply, a cell has exactly one accepted encoding, and arbitrary or
truncated input is refused rather than fatal. Node-scale breadth stays isolated: the
large-bag, lazy, and random-access paths are separate children, and bag-of-cells
compression is behind the `compress` feature off the default build ([NET-ADR-009],
[NET-ADR-010]).

### Milestone 2: The write path and wallets

Delivers: a trust-minimized read-and-send client. It constructs an external message,
sends it with confirmation, and can follow a transaction to its result, and it carries
the wallet contract families, seed phrases, hierarchical derivation, and TON Connect
proof verification ([NET-ADR-003]). This reaches the floor the project holds itself
to: a client that can back a wallet end to end.

Depends on: Milestone 1. A message is a tree of cells.

Gate: the write path's first contact with key material is a signer seam. The caller
supplies the signing operation, and the library never holds or sees a private key or a
seed. The mnemonic standard and the derivation scheme are settled in a security review
before that code is written ([NET-ADR-003]). The floor is observable as a real
transfer sent and then read back in a proven account read ([NET-ADR-001]).

### Milestone 3: The full TL-B type set

Delivers: the whole TL-B type set decoded from cells, past the block and account
subset a verified read needs today, so a consumer can read the full structure of
blocks, transactions, and messages.

Depends on: Milestone 1.

Gate: decoding and checking stay separate operations. A decoded value is a
server-reported value until a proof checks it, and every new type is read under the
panic-free decode lints, refusing hostile input rather than unwinding ([NET-ADR-002],
[NET-ADR-003]).

### Milestone 4: The liteserver method set and a connection pool

Delivers: the full liteserver query set past the three reads that ship today, and a
connection pool so reads spread across servers and a slow or hostile server does not
stall the client. The write path's `sendMessage` rides this pool ([NET-ADR-003]).

Depends on: Milestone 3 for the response types, and Milestone 2 for the send it
carries.

Gate: a new method's response stays server-reported until it is checked, and the pool
does not let a server size the client's work. The bound discipline that block sync
already holds, counts read off the wire before any proof is parsed or any signature is
touched, extends to the pool ([NET-ADR-005]).

### Milestone 5: ADNL over UDP and the DHT

Delivers: ADNL over UDP with channels, and DHT read and write with record signature
verification, so the client discovers peers and address records over the network
rather than from a fixed liteserver list. It reads DHT records and publishes its own.

Depends on: the TL codec and the ADNL crypto that ship today.

Gate: DHT record signatures are verified. The client and node boundary holds and is
observable as an absence: no crate serves DHT values to other peers ([NET-ADR-003]).

### Milestone 6: RLDP, overlays, and QUIC

Delivers: RLDP, overlays, and QUIC, the reliable-datagram and overlay transports the
most demanding consumers need.

Depends on: Milestone 5. RLDP runs over ADNL, and overlays are discovered through the
DHT.

Gate: these paths are feature-gated off the default build, so the mobile and wallet
binary size is unchanged ([NET-ADR-001], [NET-ADR-009]). The boundary holds: an
overlay is joined and read, and full-block exchange as a participant stays out
([NET-ADR-003]).

### Milestone 7: The local TVM

Delivers: a local TON Virtual Machine that runs get-methods against proven code and
data, so a computed result, a jetton balance being the common case, becomes trustless.
The result is surfaced in a type in the verified family, distinct from a
server-reported one. This is the last large component ([NET-ADR-007]).

Depends on: Milestone 1 for the cells the machine runs over, and the proven code and
data the read path already returns.

Gate: the differential harness comes before the first opcode. Continuous integration
builds a pinned reference C++ TON emulator, and every opcode lands with the
differential cases that grade it against the emulator, never ahead of them. The replay
corpus is captured from mainnet and re-derived against the emulator. Each opcode
declares its minimum global version, and an inventory test asserts the table complete
against that set. The heavy crypto primitives, the BLS12-381 pairing and the secp256k1
curve, come from established single-copy crates ([NET-ADR-007], [NET-ADR-004]).

### Milestone 8: Contract helpers and an HTTP fallback

Delivers: contract helpers, typed wrappers over the get-methods and message formats
the TVM and the write path now support, and an HTTP fallback client for an environment
that cannot open an ADNL socket.

Depends on: Milestone 7 for the get-methods the helpers wrap, and Milestone 2 for the
messages they build.

Gate: the type discipline holds regardless of transport. The HTTP fallback cannot
carry a proof, so it returns a server-reported value and never a verified one, and
adding it never weakens a verified read ([NET-ADR-003]).

### v1.0.0: Full parity, the API frozen

Delivers: the whole surface of [NET-ADR-003], composed and complete. The read path,
the write path and wallets, the full TL-B set, the full liteserver set and pool, ADNL
over UDP and the DHT, RLDP, overlays and QUIC, the local TVM, contract helpers, and
the HTTP fallback.

Gate: full parity, including the TVM, and the API frozen because the client is
genuinely complete ([NET-ADR-001], [NET-ADR-007]). The core is audited by the
project's internal capability rather than a paid external firm. The bindings beyond
Node, the browser build over a WebSocket transport and the Python, Swift, and Kotlin
bindings, follow after the core reaches parity; each stays thin, holds no
verification, and takes its error codes and its epoch from the core ([NET-ADR-008],
[NET-ADR-002]). After 1.0.0 the observable API is stable, and the verification epoch
continues to track moves in the accept and reject boundary independently of the
version.

## What could move v1.0.0

The date is not fixed, and completeness is preferred over an early label
([NET-ADR-001]). Four things carry the most schedule risk.

- The local TVM (Milestone 7) is the largest component and the most likely to move the
  release. It is placed last for that reason, and it is gated on a differential harness
  that must agree with a pinned emulator opcode for opcode before any of it is trusted
  ([NET-ADR-007]). Until it lands, a computed contract result stays server-reported.
- The cell engine (Milestone 1) underlies everything. It is the base every later
  milestone reads, so a correctness change there reaches the whole sequence above it.
- Wallet key handling (Milestone 2) touches custody. The signer seam, the mnemonic
  standard, and the derivation scheme are settled in a security review, and every
  change on that path runs the custody gate before it ships ([NET-ADR-003]).
- One maintainer. The library is maintained by a single maintainer, and its schedule
  flexes to that capacity. Its cadence is its own, and a consumer pins the version it
  wants rather than waiting on a release ([NET-ADR-001]).

## The ceiling

The sequence ends at a complete client and goes no further. Catchain and the validator
session, full-node block exchange as a participant, TON Storage, TON Sites, and block
production are out of scope and stay out. Those are what a node or a validator does.
ton-net consumes the network and verifies it ([NET-ADR-003]).

## References

- [NET-ADR-001]: purpose and priorities.
- [NET-ADR-002]: one audited core, a sans-I/O seam, thin bindings.
- [NET-ADR-003]: client scope and the write path.
- [NET-ADR-004]: vetted dependencies and one copy of each crypto primitive.
- [NET-ADR-005]: the trust anchor and signature-checked block sync.
- [NET-ADR-006]: validator signature verification.
- [NET-ADR-007]: the local TVM and the differential harness.
- [NET-ADR-008]: versioning, the verification epoch, and the binding sequence.
- [NET-ADR-009]: flat layered crates and how a crate grows.
- [NET-ADR-010]: BoC compression behind a feature.
- [architecture.md]: the layers, the transport seam, and where the trust lives.

[NET-ADR-001]: adr/NET-ADR-001-purpose-and-priorities.md
[NET-ADR-002]: adr/NET-ADR-002-architecture.md
[NET-ADR-003]: adr/NET-ADR-003-scope-and-write-path.md
[NET-ADR-004]: adr/NET-ADR-004-dependencies.md
[NET-ADR-005]: adr/NET-ADR-005-trust-anchor.md
[NET-ADR-006]: adr/NET-ADR-006-signature-verification.md
[NET-ADR-007]: adr/NET-ADR-007-tvm.md
[NET-ADR-008]: adr/NET-ADR-008-versioning-and-bindings.md
[NET-ADR-009]: adr/NET-ADR-009-code-structure.md
[NET-ADR-010]: adr/NET-ADR-010-boc-compression.md
[architecture.md]: architecture.md
[the changelog]: ../CHANGELOG.md
