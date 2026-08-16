<!--
SPDX-License-Identifier: Apache-2.0
SPDX-FileCopyrightText: 2026 Nirapod Labs
-->

# ton-net architecture

ton-net is a Rust client for The Open Network. It connects to a TON liteserver
over the network's own transport, reads chain state, and verifies every answer
against validator signatures rather than trusting the server that sent it. One
audited Rust core does that work, and language bindings expose it without
reimplementing it.

The core is a client and stays one. It consumes the network and checks it. It
does not serve values to other peers, host storage or sites, exchange full blocks
as a participant, run consensus, or produce blocks. Growth means a more complete
and more widely adopted client, never a move toward running network
infrastructure.

This document maps the layers, the seam that keeps the protocol code free of I/O,
the single trust guarantee the API is built around, and the shape of the
repository.

## The layer stack

The library is one crate, `ton-net`, whose source is `core/src`, plus the bindings
under `bindings/`. Each layer is a module of that crate with one job, declared in
`core/src/lib.rs`. From the wire up:

- **`tl`, the TL codec.** TON's Type Language is the wire format for ADNL
  envelopes and liteserver queries. This module defines the typed messages the
  client reads and writes and derives their encode and decode over `tl-proto`. It
  performs no I/O and checks nothing: a decoded response is the server's word until
  a higher layer verifies it. It covers the ADNL message envelope, the liteserver
  query and response set, and the two messages a validator signature covers.

- **`cell`, the cell model and bag-of-cells codec.** A cell is TON's
  universal container, up to 1023 bits of data and up to four references, forming a
  directed acyclic graph that every TON structure is built from. This module parses
  the serialized bag-of-cells form, builds cells, reads typed values out of them,
  computes the SHA-256 representation hash, and implements the exotic-cell and
  level-mask rules that make Merkle proofs checkable. It also carries the TON
  dictionary, because the cell model owns it. It sits at the foundation
  because that model belongs to no single higher layer: a proof, a block, and a
  wallet all need it. Parsing treats its input as hostile and returns an error
  rather than panicking or allocating on a declared size it has not checked.

- **`adnl`, the ADNL channel.** ADNL is the encrypted transport TON nodes
  speak. This module opens a liteserver session over it and runs a query to its
  answer. Its protocol core is pure: building the handshake packet, deriving the
  session ciphers, and sealing and opening the stream frames are synchronous
  functions over bytes, tested against fixed vectors, with no socket and no clock.
  The I/O sits behind a seam described below.

- **`lite`, the liteserver client.** This module speaks the liteserver query
  protocol over an ADNL connection and decodes the read responses into cleaner
  domain types. It checks nothing. A read comes back as a `ServerReported` value,
  and the proof bytes travel with it for the layer above to verify. It reads the
  masterchain head, an account's raw state at a given block, and the proof links
  between two blocks.

- **The DHT client (planned).** Peer and address discovery over TON's distributed
  hash table is in client scope and is not yet built. A network config already
  carries a DHT section, which this release parses past and does not read. Its job,
  once built, is to resolve peers and address records over the network rather than
  from a fixed server list, and it stands beside the liteserver client as the other
  way to reach the network.

- **`tlb`, the block structures, and `proof`, the proof engine.** `tlb` turns
  the cells a liteserver returns into account and block values, and `proof` is where
  responses are checked. `verify_chain` checks a block-proof chain link by link,
  and `verify_account` checks an account read against a trusted block hash by
  recomputing every Merkle hash from the bytes the server sent. Decoding and
  checking are separate operations, which is why they are separate modules, and
  `tlb` decodes only what a read or a proof needs, not a block's whole transaction
  set or a shard state's queues.

- **Block-sync, in the facade.** Block-sync is what turns a pinned
  starting block into a current one the client proved for itself. It walks from the
  key block the config names to the network's head, checking a validator signature
  set at every step, and bounds the walk so a server cannot decide how much work
  the client does.

- **The TVM (planned).** A local TON Virtual Machine to run get-methods against
  proven code and data is the last large component. It is not built. Until it is, a
  computed contract result would be server-reported rather than proven, which is the
  gap it closes.

- **The facade, at the crate root and in `client`.** This is the API most consumers
  use. It owns the connection lifecycle, address parsing, the bundled network config,
  block-sync, and the type distinction between a proven read and a reported one. The
  lower modules are reachable but not the surface the API is designed around; the
  root re-exports the handful of their types a caller needs.

- **`bindings/node`, the bindings.** The Node.js binding wraps the facade with
  napi-rs and presents it in JavaScript-native shapes. It is the first binding, and
  more are planned over the same core.

## The transport seam

The ADNL protocol logic is sans-I/O. It produces bytes to send and consumes bytes
received, and it touches no socket and no clock. The one thing that moves those
bytes over a real link is a `Transport`, a two-method trait (`write_all`,
`read_exact`) in `adnl`. `TcpTransport` implements it over TCP and is the
native default. Nagle's algorithm is disabled on it, because ADNL is a
request-and-response protocol where a small frame should go out at once rather than
be held for coalescing.

Keeping the seam this narrow is a deliberate decision (NET-ADR-002, the sans-I/O
split), and it has two payoffs. First, the protocol core, a security-critical
handshake and stream cipher, is testable against fixed vectors with no network in
the loop. Second, the same connection driver runs over a different link without the
protocol code changing: a browser WebSocket transport is planned, and it implements
the same trait, so a build targeting the browser reuses the whole ADNL, liteserver,
and verification stack unchanged. The trait's methods return `impl Future + Send`
rather than using `async fn` so the `Send` bound is explicit, which the generic
driver needs to run on a multi-threaded runtime.

The seam is why the crate pulls only the narrow tokio features the transport and the
call timer need, and why both sit behind the `net` feature: a build with
`default-features = false` carries the handshake and the frame crypto and no socket
at all. The socket and the async runtime belong to the caller, not to the library.

## One core, every language

ton-net is one Rust implementation with thin bindings on top, not one
implementation per language. The whole of the protocol and, more to the point, the
whole of the verification live in the Rust crates. A binding marshals values across
the FFI boundary and presents them idiomatically; it never re-decides what is valid.

The reason is the trust guarantee. Proof verification is the point of the library,
and a second implementation is a second place for a proof-acceptance bug to live.
Reimplementing the Merkle and signature checks per language would multiply the audit
surface by the number of languages and let the implementations drift, so a proof a
Rust caller rejects could be one another language's caller accepts. Concentrating
every check in one audited core means every consumer inherits the same acceptance
boundary, and an audit or a fix lands once for all of them.

The Node binding shows the division of labor. It maps a u64 shard to a hex string, a
balance to a decimal string because a JavaScript number would round it silently, and
hashes and cells to buffers, and it forwards each call straight into the facade. The
error codes it throws come from the core's own error type rather than a table it
keeps, so a variant added to the core is a build failure in the binding rather than a
silent `UNKNOWN` in JavaScript. The one property the core enforces with a private
type, an unforgeable proven value, is documented in the binding as a label rather
than a guarantee, because a plain JavaScript object cannot carry it. Saying so
plainly is the seam working as intended: the binding states exactly what it can and
cannot promise.

## Where the trust lives

Everything the library is for reduces to one guarantee: a value it calls proven sits
in the state of a block that traces back, by cryptography alone, to a single pinned
starting point. Three parts hold it up.

**Block-sync establishes a trusted block.** A `Client` starts from the init block the
config pins, a masterchain key block, and walks forward to the network's current
head. Each link in the walk carries the destination block's header proof and a set of
validator signatures, and a link is believed only once more than two-thirds of the
source key block's validator set has signed for it. The walk always keeps a key block
as its anchor, never the head, because only a key block carries the validator set that
makes the next step checkable. The result is a current masterchain block the client
proved for itself rather than one a server named.

**The proof engine checks responses against that block.** Given a trusted block hash,
`verify_account` recomputes a chain of Merkle hashes from the bytes the server sent
and requires each to equal a hash the previous step already established. For an
account outside the masterchain, the shard block that holds it is derived from the
masterchain state rather than taken from what the server named. The account's own
state bytes are hashed and required to equal the hash the proof binds into the block.
Nothing the server says is believed except what the arithmetic forces, and a proof
that merely declines to cover an account fails rather than reading as an empty answer.

**The API encodes proven and reported as different types.** A `ServerReported<T>` is
the server's word, returned with the proof it sent unchecked. A `Verified<T>` was
checked against a trusted block. `Verified` has no public constructor, so a value of
that type exists only where this crate did the checking, and there is no way to turn
the first into the second. The read with the plain name, `Client::account`, is the
proven one; the unchecked read is named `account_reported` for what it is. The safe
path is the default, and the unchecked path is the exception a caller has to ask for
by name.

Two inputs stay trusted, and the library names both. The pinned init block is the
root of trust: everything else is derived from it, so it is worth exactly what the
source it came from is worth, and fetching a fresh config moves that root to whoever
served it. The local clock is the other: a proof establishes that a block is real and
was committed but says nothing about when it was served, so a genuine old block
replayed passes every cryptographic check and is caught only by comparing the block's
generation time against the clock. A clock far enough behind is reported rather than
obeyed, so the freshness check never silently stops running.

One more number tracks this guarantee. `VERIFY_EPOCH` is a version for the acceptance
boundary itself, kept separate from the API version, because what the library accepts
as proven can change while the API stays fixed and can stay fixed across an API break.
A caller that stored a verified result can compare the epoch it was checked under
against the current one and decide whether to check again.

## Correctness first, performance within it

Correctness and safety are the floor and win any real conflict, and the code holds
that floor structurally. The library crate forbids unsafe code, and the compiler
holds it there, since an inner allowance of a forbidden lint is an error rather than
an override. Unsafe code exists in exactly two places outside that root. The node
binding cannot forbid: the macro that generates its bridge expands to unsafe code
carrying its own allowance, so a binding root that forbids does not compile. It denies
instead, and because a deny is what an allowance silently defeats, a check reads the
binding's own source text for one. And a crate root's lint does not reach a test
binary, so the allocation-counting test target implements a global allocator in unsafe
code of its own. Every decoder that reads bytes from a peer the client does not
trust returns an error rather than unwinding,
because a panic in a decoder is a denial of service in whatever process embedded it,
and parsing refuses a bag of cells past its cell and depth bounds before it allocates
on a size it has not checked.

The floor is not permission to be slow. Where a server could otherwise make the client
do unbounded work, the bound is part of the design rather than a later hardening pass.
Block-sync refuses an oversized reply on counts read straight off the wire, before any
proof is parsed or any signature is touched, and the signature check spends a curve
operation only on a validator it has not already counted, so a set padded with
duplicates cannot amplify the cost. Performance is bought with sound engineering rather
than shortcuts: the external dependency tree keeps a single copy of each crypto
primitive, optional features stay off the default build, the chosen crates parse
cleanly to wasm so the same core runs in a browser, and the cell type is immutable so
it can be shared without copying.

## Repository shape and the one-way layering

The layers are flat modules under `core/src`, not nested crates, and the edges between
them run one way. Two modules name no other and sit at the foundation. Each higher
module names only modules below it, and the facade at the top reaches the four it
needs. The binding depends only on `ton-net`.

```
bindings   ton-net-node    Node.js binding      -> ton-net

facade     root + client   API and block-sync   -> lite, adnl, proof, tlb

client     lite            liteserver reads     -> adnl, tl

protocol   adnl            ADNL channel         -> tl
           tlb, proof      blocks and proofs    -> cell, tl

foundation tl              TL codec             (names no other module)
           cell            cell model and BoC   (names no other module)
```

Every arrow points down this ladder, and no module below the facade names anything
above it. One pair on the same rung names each other: `tlb` decodes a block header
through a Merkle proof `proof` checks, and `proof` reads the structures `tlb` decodes.
They were one crate before the collapse, so the ladder is stated as one direction
rather than as an acyclic graph, and it is that direction the build checks.

`scripts/check-layers.mjs` is what holds it. Reading a dependency graph was the wrong
instrument, because `std` needs no dependency edge and a socket opened inside a
foundation layer would have compiled with nothing to notice. The check reads the source
text of the four deciding layers instead and refuses any of them naming `adnl`, `lite`
or `client`, naming tokio or getrandom, or reaching the socket, the filesystem, the
process, the environment, a thread or a clock. `lite` is held separately to not naming
`cell`, because a liteserver answer leaves that layer as the bytes it arrived as. Every
refusal is run first against probes built to trip it, and the same reading has to find
the three edges that are supposed to be present, so a pattern that has stopped matching
reports itself broken rather than reporting the tree clean.

What the one-way direction buys a consumer is a build that stops where the consumer
does. `default-features = false` drops tokio and the socket and keeps the cell engine,
the typed structures, the proof engine, the ADNL handshake and frame crypto,
`Verified`, address parsing and the config reader, on one dependency line. The external
tree is held to a single copy of each crypto primitive on purpose: the signature curve,
the digest, and the ciphers are shared rather than duplicated. Optional paths that a
lighter consumer does not want, JSON rendering of a cell tree and bag-of-cells
compression, are feature-gated off the default build so they cost nothing at runtime
until asked for. The library and the binding move in lockstep on one library version.

## What is still to come

ton-net is under active development toward a v1.0.0 that freezes only when the client
is genuinely complete; there is no external deadline, and completeness is preferred
over an early version label. The current releases are a read path: connect, sync, and
read an account with its proof checked against a block the client established itself.
The sequencing is dependency-first, which already places the write path early and the
TVM last among the large components.

Still to come, all of it client scope and none of it node infrastructure:

- **The write path**, so a client can send an external message and back a wallet end
  to end, not only read. This is the highest-priority remaining thread, because it is
  what a dependent wallet needs first.
- **The DHT client**, for peer and address discovery over the network rather than a
  fixed server list.
- **A browser transport**, a `Transport` over a WebSocket, so the same stack runs on a
  wasm target.
- **The local TVM**, to run get-methods against proven code and data so a computed
  result is trustless rather than server-reported.
- **Further protocol reach** that the most demanding consumers need, such as RLDP,
  overlays, and QUIC, carried as isolated, feature-gated paths that cost a lighter
  consumer nothing at runtime.
- **More language bindings** over the same core, beyond the Node binding that exists
  today.

Each addition makes a more complete client. None of it turns ton-net into a node.
