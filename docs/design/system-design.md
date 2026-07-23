# System design

## Scope of this document

This is the system design for ton-net, a direct client for the TON network written
in Rust. It describes the components the library is built from and how they compose,
the data flow of a proven account read from a pinned anchor to a verified result, the
state the library keeps and the state it refuses to keep, and the failure and security
posture at each boundary the library crosses.

The code under `crates/` is authoritative for behaviour. This document explains the
shape the code takes and why, and marks what is designed but not yet built.

## What ton-net is

ton-net reads TON chain state by speaking TON's own wire protocols, with no HTTP
indexer between the client and the network. It verifies every answer against validator
signatures rather than trusting the server that gave it. A read either proves what it
returns or fails; there is no unproven fallback.

It is a client and not a node. It consumes the network and checks it. It does not serve
values to other peers, host storage, exchange full blocks as a participant, run
consensus, or produce blocks. Growth means a more complete and more widely adopted
client, not a move toward network infrastructure.

The library is a shared Rust core bound into other languages. The core and the Node
binding are the two surfaces that work today. The architecture that keeps one audited
core rather than one implementation per language is fixed in NET-ADR-002.

## Layering and dependency direction

The workspace is six library crates and one binding, layered so that each depends only
on those beneath it.

```
                         bindings/node   (napi-rs, JS shapes)
                                |
                            ton-net       (facade: Client, Config, Address,
                                |          Verified, Error, sync, VERIFY_EPOCH)
              +-----------------+--------------------+
              |                 |                    |
        ton-net-lite      ton-net-block        ton-net-cell
        (read client)     (decode + verify)    (cells, BoC, proofs)
              |                 |    \               |
        ton-net-adnl            |     \--------------+
        (transport)             |                    |
              |                 |                    |
              +--------+--------+--------------------+
                       |
                   ton-net-tl   (TL wire codec)
```

ton-net-tl and ton-net-cell are the two roots. ton-net-cell is independent of the wire
codec: the cell model belongs to TON's data layer, not to any one protocol. ton-net-block
sits on both roots, ton-net-adnl on the codec, ton-net-lite on the transport and the
codec, and the facade on all of them.

The transport is a seam, not a fixed choice. The ADNL protocol logic is sans-I/O: it
produces bytes to send and consumes bytes received, over a `Transport` trait that moves
ordered bytes and nothing more. `TcpTransport` implements that trait over TCP today; a
browser transport is added later without the protocol code changing. This split is
NET-ADR-002.

## Components

### ton-net-tl: the TL codec

Defines the TON Type Language types the client reads and writes, derived over the
`tl-proto` crate, and re-exports the serialize and deserialize entry points. It covers
the ADNL message envelope, the liteserver query and response types, and the messages a
validator signature covers. A boxed type carries a four-byte constructor id, the CRC32
of its scheme line; a bare type, used only as a field, carries none.

This crate performs no I/O and checks nothing. A decoded response is the server's word
until a higher crate verifies it. The block-proof types it defines carry the raw proof
and signature bytes as `Vec<u8>`, because their reader is a verifier rather than a person.

### ton-net-cell: the cell model, the bag-of-cells codec, and the proof primitives

A cell is TON's universal container: up to 1023 bits of data and up to four references,
forming a directed acyclic graph. Every structure on TON is a tree of cells. This crate
holds the cell type and its four exotic kinds, the bag-of-cells parser and serializer,
the dictionary types a block is built from, cell builders, usage trees, and the Merkle
primitives.

A cell's identity is its representation hash. The hash follows the level rules that give
exotic cells meaning: at level zero a pruned branch answers with the hash of the subtree
it replaced, so a pruned copy of a tree hashes to the same value as the full tree. That
substitution is what makes a Merkle proof checkable. `virtualize` reads the tree a proof
stands for, and `create_proof` builds one.

This is the crate that reads bytes off the untrusted boundary, so it is the adversarial
parsing surface. Parsing never panics and never allocates on a declared size it has not
checked. It refuses a bag past `MAX_CELLS` (2^17) or `MAX_DEPTH` (1024), a reference that
does not point strictly forward, and a cell whose descriptors and data disagree. It
returns a `CellError` instead of unwinding. Two capabilities that only larger consumers
need, JSON rendering and LZ4 compression of a serialized bag, are behind the `json` and
`compress` feature gates so the default build carries neither. The compression admission
is NET-ADR-010.

### ton-net-block: block and account decoding, the proof engine, and validator handling

Turns the cells a liteserver returns into values a reader can use, and holds the
verification logic. It decodes only what a read or a proof needs: the account structure,
a block header, the configuration a key block carries, the state update a block names,
and the shard records a masterchain state holds. It does not read a block's transaction
set or a shard state's message queues.

Decoding and verifying are separate here, and the separation is the crate's spine. An
`Account` from `Account::decode` is bytes a server sent. The same type from
`proof::verify_account` was checked against a block hash the caller trusts. The proof
engine is a set of pure functions:

- `verify_merkle_proof` recomputes a proof's content hash and requires it to equal both
  the hash the proof stores and the root the caller demanded, and checks the stored depth
  against the content.
- `verify_block_state` reads the new-state hash out of a block's Merkle update, so a
  trusted block hash becomes a trusted state hash.
- `verify_shard_block` derives, from the masterchain state, which shard block an account's
  state has to come from, rather than believing the block the server named.
- `verify_account` chains these into one check from a trusted masterchain hash down to a
  hash bound to the account's own cell.

The chain verifier (`verify_chain`) checks a block-proof chain link by link, and the
validator handling reads the masterchain validator set from configuration parameter 34
and applies the two-thirds signature threshold. Signature verification is a separate
module built on the curve crate already in the dependency tree rather than on a second
ed25519 crate (NET-ADR-006). Both are described in the data-flow section below, because
they are the heart of a proven read.

### ton-net-adnl: the ADNL transport

Opens and runs a liteserver session over ADNL, split along the sans-I/O seam. Three
pieces:

- The protocol core is pure. `client_handshake` builds the 256-byte handshake packet and
  derives the session ciphers from the shared secret. `SessionCiphers` seals and opens the
  stream frames. These are synchronous functions over bytes, tested against fixed vectors,
  with no socket and no clock.
- I/O lives behind the `Transport` seam. `TcpTransport` implements it over TCP, disabling
  Nagle's algorithm so a small frame is sent at once.
- `AdnlConnection` is the one async object. It draws the per-session randomness from the
  operating system at the I/O edge, completes the handshake over a transport, and runs the
  ADNL message layer: it wraps a query with a fresh random id, seals it into a frame, and
  reads frames until an answer echoes that id.

The handshake derives a shared secret by Diffie-Hellman of an ephemeral Curve25519 client
key with the server's published key. Only a server holding the matching private key can
recover the session parameters and frame the session, so a completed handshake is
evidence the configured key is the key that answered. A server key that is not a valid
point, or one of small order that would collapse the secret to zero, is refused before any
session opens.

### ton-net-lite: the liteserver read client

Speaks the liteserver query protocol over an ADNL connection and decodes the read
responses into cleaner domain types. It exposes three reads: `masterchain_info` for the
current head, `account_state` for an account's raw state and proofs at a block, and
`block_proof` for the links between two blocks. It maps a wire block sequence number to an
unsigned height and sets the raw proof bytes aside in a `ServerReported<T>` wrapper rather
than mixing them into the value.

This crate checks nothing. Every value it returns wears the `ServerReported` wrapper to
say so, and the proof bytes travel on that wrapper so the layer above can verify them
without another round trip. The block-proof response is returned as the wire type, because
its every field is evidence for a verifier to weigh.

### ton-net: the facade

Composes the stack into the surface a program uses. It owns:

- `Client`, one ADNL channel to one liteserver, serving reads over it. Calls take
  `&mut self`, so overlapping calls on one client serialize over the single channel.
- `Config`, the liteserver list and the block a client anchors trust at, parsed from
  TON's `global.config.json` format, with a bundled mainnet snapshot.
- `Address`, parsing the raw and user-friendly forms with a verified checksum and tag.
- `Verified<T>`, the wrapper that marks a value proven against a block. It has no public
  constructor, so a value of this type is a claim the type system keeps honest.
- `Error` and `ErrorCode`, one closed error set with a stable per-kind code so a caller,
  in any bound language, can tell a transport failure (retry) from a proof failure (do
  not retry this server).
- `sync`, the walk from the anchor to the head with the bounds that keep a server from
  deciding how much work the client does.
- `VERIFY_EPOCH`, a number that rises when the set of things this build accepts as proven
  changes, so a caller who cached a result can decide whether to check it again.

The facade is where the read-versus-proved distinction is carried in the type. The lower
crates leave it to the caller to track; here `account` returns `Verified<Account>` and
`account_reported` returns `ServerReported<Account>`, and nothing converts one into the
other.

### bindings/node

Wraps the facade with napi-rs. Reads cross the boundary as JavaScript-native shapes, and
whether a read was proved stays visible in the shape: a `{ value, proof }` object is the
server's word, a `{ value, anchor }` object was proved. The error code is carried as a
stable prefix on each exception message, mapped from the core's `ErrorCode` rather than
re-invented per binding. The single connection sits behind an async mutex so overlapping
JavaScript calls serialize rather than corrupt the stream. Browser, Python, Swift, and
Kotlin bindings are planned; the core reaches parity before they follow (NET-ADR-008).

## Data flow: a proven account read

The safe read is `Client::account(address)`. It walks the chain to a head it proves,
reads the account at that head, and binds the account to that head, all in one call. The
value it returns rests on no hash the caller or the server chose freely: it rests on the
key block the config pins, one validator signature set at a time.

The read decomposes into three stages over the transport: block sync to a proved head,
then a raw read at that head, then the proof engine binding the account to it.

### The transport underneath every query

Each of the three liteserver reads used below travels the same path. The facade calls
into ton-net-lite, which wraps the request in a `liteServer.query` envelope and hands the
bytes to `AdnlConnection::query`. The connection wraps them in an `adnl.message.query`
with a fresh random id, seals them into a frame under the send keystream with a fresh
nonce, and writes it. It then reads frames under the receive keystream, skipping an empty
confirmation frame, until an `adnl.message.answer` echoes the query id, and returns the
answer bytes. ton-net-lite decodes those bytes as the expected response, or surfaces a
`liteServer.error` if that is what the server returned. Every call runs under a deadline:
an ordinary read at 15 seconds, a block-proof reply at 60 because it is a larger thing.

The session the frames run over was established once, at connect, by the ADNL handshake
described above.

### Block sync: from a pinned anchor to a proved head

`sync` establishes a block the client proved rather than one a server named.

It starts from the anchor if the client has one, or from the config's init block on a
first sync. The bundled mainnet snapshot names that init block at masterchain sequence
number 46894135. It reads the server's reported head and uses it only as a target to walk
toward: a head not ahead of the trusted start is refused, because there is no way to show
its block is current without a chain to it.

Then it loops, asking `block_proof(anchor, target)` and checking every reply:

1. Cheap bounds run first, before any parsing or curve arithmetic, because they are counts
   and lengths read straight off the wire. A reply may carry at most 64 links, a proof
   inside a link at most 2^20 bytes, a signature set at most 1024 signatures. A sync may
   check at most 4096 links over at most 512 replies. These refuse an oversized answer
   before the client spends work on it.
2. `verify_chain` checks the run link by link. Each link must start where the last ended,
   stay in the masterchain, and run forward. A backward link is refused by name, because
   an anchor that is always a key block never needs one. For each link the source key
   block's configuration proof yields the validator set, the destination header proof is
   required to root at the destination's own root hash, and the header's sequence number,
   shard, and key-block flag are required to match what the link claims.
3. The signatures decide the link. A block's file hash is the one field of its identity no
   Merkle proof can establish, so a destination is believed only once validators carrying
   more than two thirds of the source set's weight have signed for it. The signed message
   is rebuilt exactly, in one of two forms: the older form signs the block identity
   outright, and the Simplex form signs a finalization vote naming a candidate, where the
   candidate is required to name the block the link claims. Mainnet uses both across a long
   walk, having changed form at masterchain block 59379986.
4. Progress is required: each reply must raise the anchor's sequence number.

When a reply is marked complete, the walk requires it to have reached the target the
server itself named, then requires the proved head to be fresh against the local clock.
The client keeps not the head but the last key block on the way, because only a key block
carries the validator set a later chain continues from, and hands the head back for the
read that wanted it.

A cold sync from the pinned mainnet block was measured at 1246 links over 78 replies and
a little over two minutes in July 2026. A client that saves the key block it ended on, and
passes it to `connect_from` next time, pays a link or two instead.

### The proof engine: from a proved block to a bound account

With a proved masterchain head in hand, `account_at(address, head)` reads and binds.

It first refuses a head that is not a masterchain block, because the whole chain of
reasoning hangs off one: a shard read derives its shard block from the masterchain state,
and a masterchain read takes the head hash as its state's own. It reads the account's raw
state and proofs at the head with `account_state`, unchecked, then calls
`proof::verify_account` against the head's root hash. That check recomputes a hash from the
server's bytes at every step and requires it to equal a hash the previous step established:

1. For an account outside the masterchain, the shard proof is checked first. It roots at
   the trusted block hash, exposes the block's state update to reach the masterchain state,
   and the masterchain state's shard records give the root hash of the shard block holding
   the account. Descending the workchain's shard tree by the account's leading address bits
   is the coverage check: there is no other shard the account could be in. This is what
   stops a server answering a basechain read out of a shard block of its own choosing. For
   a masterchain account this stage is skipped; the account is in the trusted block's own
   state.
2. The account-state proof roots at that block hash and exposes the block's state update,
   which names the shard state. A second proof in the same bag roots at that state and
   exposes the accounts dictionary, which gives the hash of the account's own cell.
3. The account state bytes the server sent are parsed and their root cell hashed. The root
   is required to be non-exotic and to have a zero level mask, which rejects a pruned branch
   standing in for the account's code or data: a pruned branch answers at level zero with
   the hash it replaced, so without this check a placeholder's bytes could read as proved
   contract state. The root's hash is then required to equal the hash the proof bound to the
   block.

An account the proof shows is not in the state comes back as a proved `Nonexistent`, not a
failure. An account the proof merely declines to cover is the failure `NotCovered`. A state
the proof contradicts is `NotBound`. On success the account is wrapped as `Verified`,
tagged with the block it was proved against.

The representation hash is the pivot of the whole flow. Every binding, block to state,
state to account, is one recomputed hash required to equal one already established, so
nothing the server says is believed except what the arithmetic forces.

### The local TVM step (planned)

A proven read gives back an account's code and data as proved cells. Some values a caller
wants are not stored fields but the result of running a get-method, a jetton balance being
the common case. A local TVM would run that get-method against the proven code and data, so
the computed result is trustless rather than server-reported. This step is planned, not
built: today a TON balance is a proven read and a jetton balance is not. The TVM is the
last of the large components in the sequencing, and v1.0.0 is not reached without it.

## State and storage

The library is a client, not a node, so it is near stateless. It keeps a live connection
and a small root of trust, and nothing else persists.

Ephemeral and in-memory, for the life of a `Client`:

- The ADNL session: the two AES-256-CTR keystream positions and the flag that records
  whether this side still knows its place in the stream. These are a moving counter shared
  with the server; a `Client` is not cloneable because only one caller may advance them.
- The TCP socket behind the transport.
- The anchor, the key block trust currently rests on, held as `Option<BlockIdExt>` and
  `None` until a sync sets it. The init block the config named, and the freshness bound.
- The per-sync walk counters. These live only across one call.

Dropping the `Client` drops all of it. The library writes no file and chooses no storage
location.

Caller-provided and read-only:

- The `Config`: the liteserver list, the init block, the freshness bound. It holds only
  public data. Its DHT section is not read.
- An anchor passed to `connect_from`, or a trusted block passed to `account_at`. These are
  public block identities, two hashes and some coordinates, and hold no secret. Each is a
  root of trust, so where a caller keeps one is the caller's decision under the caller's own
  threat model; the library stores none and names no location.
- The bundled `mainnet.config.json`, compiled in and read-only.

Never stored, at any point:

- No user key, ever. The read client takes no private key as an argument anywhere, and none
  exists in the codebase. The only secrets the library handles are the per-session ADNL
  values: the ephemeral Curve25519 key seed, the 160 session parameters, and each frame
  nonce and query id. All are drawn fresh from the operating system at the I/O edge, used to
  derive the session ciphers, never persisted, and never a user key. A wrong or hostile
  server can stall or lie; it cannot obtain a key from a library that holds none.

## Failure and security posture

Every boundary the library crosses is treated as adversarial. The library crates deny
panic, unwrap, and unchecked indexing, so a decoder fails by returning rather than by
unwinding, because a panic in a decoder reading a peer's bytes is a denial of service in
the process that embedded it.

### Unreachable peer

`TcpTransport::connect` gives up after a 10-second connect timeout. `Client::connect` tries
the config's liteservers in turn until one completes a handshake, and reports
`Error::Transport` if none is reachable or `Error::Handshake` if the one reached presents a
key that is not the configured one. Every read runs under its own deadline and returns
`Error::Timeout` rather than hanging.

### Malformed packet

A frame carries a checksum over its nonce and payload; a corrupted or tampered frame fails
it with `FrameError::Checksum`. A decrypted length prefix outside the accepted frame range,
which is what a wrong handshake produces on the first frame, is refused as an implausible
length before any allocation follows it. Bytes that decrypt but do not decode as a known
ADNL message are skipped, not fatal, because ADNL has more message kinds than the two the
client models. A response that does not decode as its expected type is `Error::Decode`. A
bag of cells that is truncated, over the cell or depth ceiling, or internally inconsistent
is a `CellError` surfaced as a failure, never a crash.

### Forged record and tampered proof

This is what the proof engine exists for. A forged account, a proof for a different block,
a proof that prunes away the account and claims a value anyway, or a pruned branch
substituted for real contract state all fail: the recomputed representation hash does not
match, the proof does not root where it was required to, the pruned dictionary reads as
`NotCovered` rather than as empty, or the non-zero level mask on the account root gives the
substitution away. A signature set forged or lifted from another block fails the two-thirds
weight check, or fails because the rebuilt signed message names a block the link does not
claim. The threshold is strictly greater than two thirds, computed in integer arithmetic
with no floating point, because the thinnest real mainnet link clears the threshold by
about four thousandths of one percent and a comparison at that margin done in `f64` is a
coin toss. Out of the proof engine, every one of these failures reaches the caller as
`Error::Proof`, distinct from `Error::Sync` for a chain that never established a block at
all, so a caller knows that asking the same server again is the wrong response.

One class of forgery the proofs cannot catch is a genuine old chain replayed: a proof says
a block is real and was committed, not when it was served. The local clock catches that.
A proved head older than the freshness bound is `Error::Stale`. A proved head far enough
ahead of the local clock, which validators do not produce, is reported as `Error::ClockBehind`
rather than silently switching the freshness check off, because the age computation
saturates and a clock a year behind would otherwise read every old block as new. The
remedy for one is another server; the remedy for the other is a correct clock, and the two
errors keep them apart.

### Amplification

A server chooses how much a client is asked to do, so every place where that could become
unbounded work is capped. The sync bounds above refuse an oversized reply from counts read
off the wire, before any proof is parsed or any signature is checked. Signature
verification runs before deduplication, which is the sound order but means a set padded
with copies of one signer would cost a curve operation each, so a per-set budget of twice
the set size bounds the curve work an honest set never approaches. The frame layer refuses
a body past a fixed ceiling before allocating for it. The cell parser refuses a bag past
its cell and depth ceilings. Small-order handshake keys are refused so a degenerate session
cannot be forced. A walk that has run longer than the freshness bound stops, because
nothing it can still reach would be fresh enough to accept, which turns a server that
answers slowly forever into a bounded failure.

A session that loses its place in the stream, which a read cancelled at its deadline can
cause, is marked and cannot be reused: it surfaces as `Error::ConnectionLost`, and the
caller opens a new client rather than retrying on a dead one.

### Custody

The library holds no user key by construction, and this is structural rather than a policy
applied on top. The current surface is read-only. No entry point accepts a private key, no
code path signs, and the only key material anywhere is the ephemeral, per-session transport
randomness described under State and storage.

The write path is designed to preserve this and is planned, not present. When it lands, its
custody posture is that the library broadcasts already-signed bytes: `sendMessage` carries
an external message the caller built, and signing happens behind a signer seam so key
material stays outside the library. The library never sees a key on the write path any more
than it does on the read path. Until that path ships, sending a transaction is out of scope
for the code, and this section describes an intended boundary rather than an implemented
one.

## Trust boundary

A verified read rests on exactly two inputs the library does not derive.

- The block the config pins. A walk has to start somewhere. It comes from the same file
  that decides which network the client is on, it is one visible block identity, and a
  caller who does not want to trust that file supplies their own starting block to
  `connect_from`. Fetching a fresh config trusts its source for that anchor, which is a
  heavier decision than refreshing a server list, because the server list needs no trust:
  every server answer is checked against a proof.
- The local clock, for freshness alone, as described above.

Everything else is derived and checked. The `Verified<T>` type is the boundary made
visible: it has no public constructor, so a value of that type exists only where this crate
checked the proofs. The claim it carries is relative, the value is as trustworthy as the
block in its anchor and no more, which is why where that anchor came from is the question
the type cannot answer on its own and `sync` is what settles.

## Performance posture

Correctness and safety are the floor and win any real conflict. That is not license to be
slow: the deliverable is correctness and safety delivered performantly, and a capability
that is correct and safe but needlessly slow is not finished. Performance is pursued within
the safety floor through sound engineering, not through unsafe or unauditable shortcuts.

Several choices in the flow above are that principle in practice. The transport is a
zero-cost trait seam, so the browser and native runtimes share one protocol core with no
runtime indirection cost to either. The cheap wire-count bounds run before any parsing or
curve work, so an oversized answer is refused for the price of reading a length. The
two-thirds weight check short-circuits the moment the threshold is cleared, sparing about a
fifth of the curve work of a full set on the common path, while still summing the whole set
on the one path that needs the total. Verification stops at the first failure. A saved
anchor turns a thousand-link cold walk into a single link. Consumer breadth that only larger
users need is carried behind feature gates so a wallet build pays for none of it, under the
guard that no scale capability may degrade the core: the immutable cell type, the mobile
binary size, or the plain read-and-build API.

## What is built and what is planned

The read path is built and runs on mainnet: the TL codec, ADNL over TCP, the liteserver
query layer for account reads, cell and proof verification, and key-block sync with the
two-thirds signature check. The current crate version is 0.3.0. The current milestone
brings the cell engine to full capability, builders and dictionaries and usage trees and
Merkle-proof creation, not parsing alone.

The following are designed and sequenced but not yet in the code. The order is
dependency-first, which places the write path early and the TVM last. Each is described
here as planned so it is not mistaken for present behaviour.

- The write path: external messages, `sendMessage`, and wallet support behind a signer
  seam. This is the floor the project holds itself to, a trust-minimized read-and-send
  client able to back a wallet end to end.
- The remaining liteserver queries: transactions, config, blocks, running a get-method, and
  sending a message.
- ADNL over UDP and peer-to-peer channels, and the DHT for resolving an ADNL address to an
  IP and publishing a record.
- RLDP, overlays, and QUIC.
- The local TVM, running a get-method against proven code and data so a computed result is
  trustless.
- The further language bindings: browser, Python, Swift, and Kotlin, after the core reaches
  parity.

v1.0.0 is the whole surface a TON client speaks, plus the write path, across the Rust core
and the Node binding, and the API freezes only when the client is genuinely complete.
Completeness is preferred over an early version label.
