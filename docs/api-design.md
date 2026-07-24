<!--
SPDX-License-Identifier: Apache-2.0
SPDX-FileCopyrightText: 2026 Nirapod Labs
-->

# ton-net API design

ton-net is a Rust client for The Open Network. It reads chain state from a
liteserver and checks every answer against validator signatures rather than
trusting the server that sent it. The API exists to make that check the default
and to make skipping it a thing a caller has to ask for by name.

One principle organizes the whole surface: a read either proved what it returns
or it did not, and which one it is has to be visible in the type, not left to a
comment or a caller's memory. Everything below follows from that. The proven
read wears the plain method name, the unchecked read is spelled out, and the two
results are different types that do not convert into each other. This is the
discipline NET-ADR-001 fixes as the reason the library exists, expressed as an
API a consumer cannot accidentally step around.

This document maps the facade a consumer imports, the two-kind read model, the
naming that keeps the safe path default, the client lifecycle that establishes
trust, the error surface, the verification epoch, and how the same surface
crosses into the Node binding.

## The closed facade

A consumer depends on one crate, `ton-net`, and imports from one place. The
library is built as a stack of small crates, but the lower crates are internal.
The facade re-exports the handful of their types a caller needs and hides the
rest, so the import surface is closed and small rather than the whole workspace.
This is the one-core, thin-surface arrangement of NET-ADR-002: the protocol and
the verification live in the Rust core, and what a consumer sees is a narrow
window onto it.

The re-exported surface, grouped by where each type is defined:

- From the facade itself: `Client`, `Config`, `Address`, `Error`, `ErrorCode`,
  `Verified`, `SyncReport`, the free function `verify_account`, and the constant
  `VERIFY_EPOCH`.
- From the liteserver layer: `ServerReported`, `BlockIdExt`, `MasterchainInfo`,
  `AccountState`.
- From the block layer: `Account`, `AccountStatus`, `AccountRead`, `Coins`.
- From the cell layer: `Cell`, `CellType`.

The facade owns the connection lifecycle, address parsing, the bundled network
config, block-sync, and the type distinction between a proven read and a
reported one. A caller who needs only the cell model or only a decoded account
can depend on the lower crate directly, because each crate is publishable on its
own, but the facade is the surface the API is designed around and the one this
document describes.

## Two kinds of read

Every read returns one of two wrapper types, and the wrapper is the answer to
"was this proved".

`ServerReported<T>` is the server's word. The value was decoded from the wire,
and the proof bytes the server sent travel alongside it unchecked. Reaching the
value says nothing about whether it is true, only about what a server claimed.
Its accessors are `value` for a borrow, `into_value` to take ownership, `proof`
for the raw unchecked proof bytes, and `try_map`, which reads something out of
the value while keeping the proof attached, because decoding a reported value
leaves it exactly as unproven as it was.

`Verified<T>` is a value proved to sit in the state of a block the caller
trusts. Its Merkle proofs were recomputed to root at a block hash, and the value
was bound to that block's state by hash, with nothing the server said taken on
trust along the way, including which shard block held the account. Its accessors
are `value`, `into_value`, and `anchor`, the last returning the `BlockIdExt` the
value was proved against.

The two cannot be flattened into one. `Verified<T>` has no public constructor:
the only way a value of that type comes into being is where this crate checked
the proofs, and no function turns a `ServerReported<T>` into a `Verified<T>`. A
`Verified<T>` in a function signature is therefore a claim the type system keeps
honest rather than a convention a caller can opt out of. This is the point of
NET-ADR-001 rendered as a type: the guarantee is not that a caller remembered to
verify, it is that an unverified value cannot wear the verified type.

What `Verified<T>` asserts is relative. The value is as trustworthy as the block
in its anchor and no more, and that block's own worth depends on where it came
from. A block a caller handed in is trusted exactly as far as the caller trusts
it. A block the client proved for itself, through `sync`, rests on the pinned
starting point and the validator signatures checked along the way. The type
carries the proof; it does not carry the provenance of the anchor, and the
naming below is built so the provenance is not lost by accident.

## Default-safe naming

The reads on `Client` are named so the proven one is the one a caller lands on
without choosing.

`account` is the proven read with the plain name. It walks the chain to a
current head the client proves for itself, reads the account there, and checks
the proofs against it, so nothing in the result rests on a block the caller
supplied. It returns `Verified<Account>`. Every call walks, which is a link or
two after the first sync but is not free, so a caller reading many accounts is
directed to sync once and reuse the head.

`account_at` is proven against a block the caller names. It takes a trusted
`BlockIdExt` and returns `Verified<Account>`, checking the account against that
block's root hash and, for an account outside the masterchain, deriving the
shard block from the masterchain state rather than believing what the server
named. The block is taken on faith, so where it came from is the whole question:
a head read from `masterchain_info` on the same client proves nothing, because
that only shows the server agrees with itself. The two anchors that mean
something are a block this client proved, from `sync` or `anchor`, and a block
the caller trusts independently. An account the block's state does not hold comes
back proved as `AccountStatus::Nonexistent`; an account a proof declines to cover
is a failure, not an empty answer.

`account_reported` is the unchecked read, named for what it is. It reads the
current head and the account at it and returns `ServerReported<Account>` with the
proof carried along unchecked. It is the exception a caller asks for by name,
because after the proven read is the default the unchecked one should not be
something a caller reaches by mistake.

`account_state` is the raw escape hatch, returning `ServerReported<AccountState>`:
the account's state and proof bytes as the server sent them, unchecked and
undecoded. It is the way out for a caller who wants to hold the proofs and check
them elsewhere, or against an anchor obtained later.

`masterchain_info` returns `ServerReported<MasterchainInfo>`, the server's
current head with no proof verified. It is reported by nature: a head is a claim
about where the chain ends, and nothing inside a proof says a block is the
newest one.

The check that `account` and `account_at` run is also available on its own. The
free function `verify_account` takes an `AccountRead` and returns
`Result<Account, Error>`, reaching no network and depending on nothing but its
argument, so the same bytes always give the same answer. It is for the case
where the bytes and the anchor arrive separately: bytes fetched now with
`account_state` and an anchor that turns up later, or bytes handed over by
something that is not this client at all. An `AccountRead` is built with
`AccountRead::masterchain` for a masterchain account, which lives in the trusted
block's own state, or `AccountRead::in_shard` for an account a shard proof ties
to the trusted block. The two constructors are separate so a shard read cannot
silently skip the step that anchors its shard.

## Establishing trust: the client lifecycle

A `Client` owns one channel to one liteserver and serves reads over it. Reads
take `&mut self`, so overlapping calls on one client run one after another over
the single channel rather than corrupting the stream; a caller who wants real
concurrency opens more than one client.

`Client::connect` dials the liteservers in a config in turn until one completes
a handshake. Nothing is proved yet: a fresh client has no anchor, and the reads
that return `Verified` values need one.

`sync` is what establishes the anchor. It walks from a starting block to the
network's current head, checking a validator signature set at every step, and
leaves the client holding a block it proved rather than one a server named.
Without a stored anchor the walk starts at the config's init block, which is a
first sync and runs over every key block published since that block: minutes and
tens of megabytes against mainnet. With an anchor from an earlier run it is a
link or two. The head the walk proves is handed back in the `SyncReport` and
then dropped; what the client keeps is the last key block on the way, because
only a key block carries the validator set a later walk can continue from.

`anchor` returns that kept key block, or `None` before the first sync. It is a
public block identity holding no secret, but it is a root of trust: anything that
can write to where a caller stores one can choose what a later client believes.
The library stores nothing and picks no location. `connect_from` takes a stored
anchor and connects and syncs from it in one call, which is how a later run stays
short.

`SyncReport` reports the head the walk proved and what the walk cost: how many
links were checked, each one a validator signature set, and how many replies the
server took. The counts are observations rather than a promise, present because a
first sync is slow enough that a caller has a right to know what it did.

Two inputs stay trusted, and the API names both. The init block is the root of
trust every proof is measured against, and it is the one thing a verified read
takes on faith from the chain's side. The local clock is the other: a proof
establishes that a block is real and was committed but says nothing about when it
was served, so a genuine old block replayed passes every cryptographic check and
is caught only by comparing the block's generation time against the clock. A head
older than the bound fails as `Error::Stale`. A clock far enough behind the chain
that the freshness check can no longer mean anything is reported as
`Error::ClockBehind` rather than obeyed, so the check never silently stops
running. The bound is `Config::max_head_age`, ten minutes by default because a
cold sync targets a head it read at the start and takes minutes to reach it, and
zero refuses every head, which is how a caller says the client should not proceed
on a proven read at all.

## Config and Address

`Config` holds the public network parameters a client needs, the liteservers to
dial and the block to anchor trust at, and never a secret. `Config::mainnet`
returns a bundled point-in-time snapshot of the public mainnet config, and
`Config::from_json` parses the standard TON `global.config.json` format.
Refreshing the config is a decision worth making deliberately, because the file
carries two things whose trust requirements are opposite: the liteserver list
needs no trust, since every answer is checked against a proof, but the init block
is the anchor every later proof is measured against, so a fetched one moves the
client's root of trust to whoever served it. `init_block` reads the anchor the
config names, `with_max_head_age` returns a config with a different freshness
bound, and `max_head_age` reads the current one.

`Address` parses both the raw `workchain:hex` form and the user-friendly base64
form, verifying the checksum on the latter and refusing a non-canonical spelling.
It exposes `workchain` and `account_id`, and the two sending hints the
user-friendly form carries, `is_bounceable` and `is_test_only`. The hints say how
a message should be sent and which network an address was written for, not which
account it is, so two addresses are equal when they name the same account
regardless of the hints, and equality and hashing run on the account identity
alone. Which network a client is on is decided by its `Config`, not by an
address, so `is_test_only` is readable but enforced nowhere: a caller that cares
checks it.

## Errors

Every fallible operation returns `Error`, a closed `#[non_exhaustive]` enum. Its
variants name the ways a read fails: a transport or handshake failure, a timeout,
a liteserver error response, a decode failure, an address or config or cell that
did not parse, a proof that did not check out, a sync that never established a
block to trust, a stale head, a clock behind the chain, and a connection that
lost its place in the cipher stream.

Because `Error` is `#[non_exhaustive]`, code outside the crate cannot match it to
the end without a wildcard arm that would swallow whatever variant is added next.
The type to branch on instead is `ErrorCode`, returned by `Error::code`. It is
the promised set of failure kinds, and `ErrorCode::as_str` gives each a stable
uppercase name for a language that has no enums. The names are a compatibility
surface, fixed once published.

Which kind of failure occurred is load-bearing, because two of the answers are
opposites. A transport failure means the socket dropped and the server may be
fine, so trying again, or trying another server, is right. A proof failure means
the server did not prove its answer, so asking it again is the reverse of what
the library is for. Keeping that distinction in the core, rather than in each
binding, is what lets every language spell it the same way. `ErrorCode` also
names `InvalidArgument`, which no `Error` value carries: the failure is a
caller's own, above this crate, and it is named here so a binding that validates
its arguments does not invent a spelling for it.

## The verification epoch

`VERIFY_EPOCH` is a single integer, currently `1`, and it answers a question the
package version cannot. A version says whether the API changed. It cannot say
whether an upgrade changed what the library accepts as proven, because the accept
and reject boundary moves independently of any signature: it can shift while
every API stays byte-identical, and it can hold fixed across a breaking API
change. So the epoch is a separate number. It rises when a new kind of proof is
accepted, when an acceptance condition tightens or loosens, when the rule for
validator signature weight changes, or when a freshness default changes, and it
moves for nothing a caller cannot observe in an accept or reject. It only ever
increases. A caller that recorded a verified result alongside the epoch it was
checked under can compare against the current one and decide whether to check
again. It is meaningless across libraries and is not a version.

## Crossing into Node

The Node binding is a thin surface over the same core, per NET-ADR-002. It
marshals values across the FFI boundary and presents them idiomatically; it does
not re-decide what is valid, and it does not reimplement a single proof check.
Reads cross as JavaScript-native shapes: a u64 shard becomes a lowercase hex
string, block heights are numbers, hashes and cells are Buffers, and a balance or
a logical time is a decimal string, because either can run past what a JavaScript
number holds exactly and a number would round it silently. The methods keep their
meaning under camelCase names: `connect`, `connectFrom`, `anchor`, `sync`,
`masterchainInfo`, `account`, `accountReported`, `accountAt`, and `accountState`
on the client, with `verifyAccount` and `verifyEpoch` as free functions and a
`Config` class carrying `mainnet`, `fromJson`, `withMaxHeadAge`, and
`maxHeadAge`.

The two-kind read model crosses as two object shapes that are never the same. A
server-reported result is `{ value, proof }`, the value with the unchecked proof
bytes the server sent. A proved result is `{ value, anchor }`, the value with the
block it was proved against. A caller cannot mistake one shape for the other, so
the distinction the Rust types enforce survives the crossing as a shape
convention.

The convention is weaker than the Rust guarantee, and the binding says so rather
than pretending otherwise. The Rust `Verified<T>` has a private constructor and
cannot be forged; the Node `VerifiedAccount` crosses as a plain object, so any
`{ value, anchor }` a caller assembles is indistinguishable from one that came
from the library. It is a label on this crate's output, not a check on an object
of unknown origin. Stating that plainly is the seam working as intended: the
binding promises exactly what it can and no more.

Failures cross as exceptions whose message opens with a stable code, the same
`ErrorCode` name followed by `": "`. A caller reads the code by splitting the
message on the first colon and branches on it, keeping the retry-or-not
distinction the core draws: a `TRANSPORT` failure is worth another attempt, a
`PROOF` failure is not. The codes come from the core's own error type rather than
a table the binding keeps, so a variant added to the core is a build failure in
the binding rather than a silent unknown in JavaScript. The one connection is held
behind an async mutex, so overlapping calls from JavaScript serialize over the
single channel exactly as `&mut self` serializes them in Rust.

## Stability and what is not here yet

The API is pre-1.0 and not frozen. Every read and response type is
`#[non_exhaustive]`, so fields and variants can be added before 1.0 without a
breaking change, and a caller matches through that rather than around it. The
freeze comes at v1.0.0, which is full client parity including the local TVM, and
it lands only when the client is genuinely complete rather than on a deadline.

The scope the finished surface reaches is the whole of what a program talking to
TON needs, and none of what a node does: it consumes the network and verifies it,
and it does not serve peers, host storage, exchange full blocks as a participant,
run consensus, or produce blocks. NET-ADR-003 fixes that boundary, and growth
means a more complete client, never a move toward running infrastructure.

Several surfaces are named in the roadmap and deliberately absent here, with no
signatures invented for them:

- The write path, so a client can send an external message and back a wallet end
  to end rather than only read. It is the highest-priority remaining thread. Its
  API is future and is not specified in this document.
- The local TVM, to run get-methods against proven code and data so a computed
  result is trustless rather than server-reported. It is the last large component,
  and its API is future.
- The DHT client, a browser transport over a WebSocket, wider protocol reach for
  the most demanding consumers, and further language bindings over the same core.

Each addition extends the surface this document describes without changing its
organizing principle: a read says in its type whether it was proved, the proven
read keeps the plain name, and the unchecked read asks for itself by name.
