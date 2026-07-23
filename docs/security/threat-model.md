<!--
SPDX-License-Identifier: Apache-2.0
SPDX-FileCopyrightText: 2026 Nirapod Labs
-->

# ton-net threat model

ton-net talks to a TON liteserver it does not trust and returns chain state a
program can act on. This document names the adversary, states what is being
protected, and points at the code that protects it. Every claim here names the
file that enforces it, and the trust properties it rests on are fixed in
NET-ADR-003, NET-ADR-005, and NET-ADR-006, above the custody position of
NET-ADR-001.

## The adversary and the asset

The adversary is the server, and anyone on the wire. A client speaks to a
liteserver over ADNL. That server is untrusted by design: it can answer falsely,
answer slowly, withhold an answer, replay an old one, or pad a real one with
junk. Anyone able to read or rewrite bytes on the network path has no more power
than the server, and the reason is structural rather than a matter of transport
hardening. Trust in this library rests on validator signatures over blocks and on
one pinned anchor, never on the identity of the peer that delivered the bytes. A
machine in the middle that rewrites every packet is still, to the verifier, a
server whose answers are checked or refused. The ADNL framing reduces on-path
tampering to that same case: a flipped byte fails the per-frame checksum, and a
desynchronized stream fails the length check, both as a `FrameError` that ends
the call rather than as data (`crates/ton-net-adnl/src/frame.rs`).

The asset is the correctness of what the client believes. The library holds no
user key and persists no secret (NET-ADR-001): the network config carries only
public data (`crates/ton-net/src/config.rs`), and the only secrets computed
anywhere are the ephemeral per-session ADNL keys, which protect the transport and
nothing of the user's. There is no key to exfiltrate and no balance to move. What
an attacker can try to corrupt is the client's picture of the chain: an account's
balance, a contract's state, which block is current. The design exists to make a
false picture fail closed as a named error rather than pass as an answer.

One guarantee frames the rest. A `Verified<T>` is as trustworthy as the block in
its anchor and no more, and it has no public constructor, so a value of that type
is a claim the type system keeps honest rather than a convention a caller can opt
out of (`crates/ton-net/src/verified.rs`). A server-reported value is a distinct
type, and there is no operation that turns one into the other
(`crates/ton-net/src/lib.rs`). The sections below are the checks that stand
between a server's bytes and a `Verified` value.

## The untrusted-decode boundary

Every byte the client reads from a peer reaches a decoder first. A decoder that
unwinds on hostile input is a denial of service in whatever process embedded the
library, so the rule is that a malformed reply returns an error and never
panics.

The rule is enforced as a lint block, identical at the top of all six crates that
touch peer bytes (`crates/ton-net-tl/src/lib.rs`,
`crates/ton-net-cell/src/lib.rs`, `crates/ton-net-block/src/lib.rs`,
`crates/ton-net-adnl/src/lib.rs`, `crates/ton-net-lite/src/lib.rs`,
`crates/ton-net/src/lib.rs`):

```rust
#![deny(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::unreachable,
    clippy::todo,
    clippy::indexing_slicing
)]
#![forbid(unsafe_code)]
```

`unwrap`, `expect`, `panic`, `unreachable`, and `todo` are denied because each is
a way to unwind on input the sender controls. `indexing_slicing` is denied
because `buf[i]` on an attacker-supplied index is the same failure spelled
differently, so slice access goes through checked forms instead: the bag-of-cells
reader advances with `checked_add` and `slice::get`, returning
`CellError::Truncated` rather than reading past the end
(`crates/ton-net-cell/src/boc.rs`, `Reader`), and frame parsing splits with
`split_at_checked` rather than by offset (`crates/ton-net-adnl/src/frame.rs`).
`unsafe` is forbidden outright, so no decode path can reach for a raw pointer to
go faster. Arithmetic is deliberately left out of the deny set: every count these
formats carry is bounded before it is used, and each subtraction sits within a
few lines of the guard that makes it safe, so denying it would bury the real
bounds under `checked_sub`.

The block is on the library, not the tests, because a test is the opposite case,
where an `unwrap` is the assertion. Two escape hatches exist and are the only
two: `Config::mainnet` uses `expect` on a checked-in file that a test in the same
module holds to parse, and the ADNL cipher constructor uses `expect` on constant
ranges of a fixed-length array. Neither sits on a path that reads peer bytes, and
each is annotated with the reason at the call site.

This boundary is the fifth of the five invariant trust properties every part of
the surface is built under (NET-ADR-003). It is what lets the sections below
assume that a hostile encoding produces an error to handle rather than a crash to
survive.

## A tampered or withheld Merkle proof

A liteserver answers a read with a Merkle proof: a copy of the block's cell tree
with the branches the answer does not need replaced by pruned placeholders. The
attack is to tamper with that proof, to substitute a placeholder for a real
answer, or to withhold the part being read and hope the client reads silence as
an answer. The defense is that a proof is recomputed against a hash the client
already trusts, never read as an answer on the server's say-so
(`crates/ton-net-block/src/proof.rs`).

`verify_merkle_proof` takes a cell and the root it must stand for. It requires
the cell to be a Merkle proof (else `BlockError::NotAMerkleProof`), requires the
root hash the proof carries to equal the expected root (else
`ProofNotAnchored`), and then recomputes the hash of the tree actually attached
and requires that to equal the expected root as well (else `ProofInconsistent`).
The recomputation is the whole point: the stored hash is a claim until the
content is hashed against it. A bag of several proof roots is selected by the
hash a root claims, which is safe precisely because the claim is then checked, so
a root that lies about what it covers fails rather than being believed
(`rooted_at`).

A withheld branch cannot pass as an answer, because a pruned placeholder reads as
nothing. When the accounts dictionary prunes away the account being read, the
lookup returns `Lookup::Pruned` and the read fails with `BlockError::NotCovered`,
which is a different outcome from a proof that the account is absent. A server
that returns a proof declining to cover the question has not answered it.

The subtler tamper is a pruned branch swapped in for an account's own code or
data. A pruned branch answers at level zero with the hash of the subtree it
replaced, so standing one in leaves the root's level-zero hash byte for byte the
same, and a check that compared only that hash would accept a placeholder's bytes
as proved contract state. The level mask is what sees it: every cell is held to
the mask its children imply, so one pruned branch anywhere below raises the
root's level above zero. `verify_account` refuses an account root that is exotic
or whose level mask is nonzero (else `BlockError::NotBound`) before it compares
the account's hash to the dictionary entry. A state that does not bind to the
proved block, an account claimed present that the proof shows absent, or an
account claimed absent with state bytes attached, all fail as `NotBound`.

For an account in a basechain shard, the shard block itself is derived rather than
believed. The masterchain records the latest block of every shard, so a proof of
the masterchain state proves which shard block an account's state has to come
from, which stops a server from answering out of a shard block of its own
choosing (`verify_shard_block`). The one input the whole chain of checks trusts
is the masterchain block root hash the caller supplies, and where that comes from
is the subject of the trust-anchor section below.

## A forged or replayed block

The trust anchor moves forward by block sync: the client walks a proof chain from
the block it trusts to the head the server reports, checking every link
(`crates/ton-net-block/src/chain.rs`, `crates/ton-net/src/sync.rs`). The server
picks the route and the client believes nothing about it. Every field of every
link is a claim until a check settles it, including which blocks the route passes
through and which direction it runs. Two attacks live here: forging a block the
validators never committed, and replaying a real block from the past.

Forgery is answered by signatures. A block's file hash is the one field of its
identity no Merkle proof can establish, being a hash of the serialized block file
rather than of the cell tree, so a header proof shows what a block says about
itself while only the signatures show it is the block the network committed
(NET-ADR-006). `verify_link` reads the validator set from the source key block's
own configuration proof, reads the destination header from its proof and requires
it to match the identity and key-block flag the link claims, rebuilds the exact
bytes the validators signed, sums the weight of the valid signatures from
distinct members, and requires that weight to carry the link. The threshold is
strict and exact (`crates/ton-net-block/src/validators.rs`):

```rust
carries(weight)  =  u128::from(weight) * 3  >  u128::from(total_weight) * 2
```

More than two thirds, promoted to `u128` so the multiplication cannot wrap, with
no rounding and no floating point. Exactly two thirds does not carry; the first
integer above it does. The denominator is summed over the masterchain signing
subset alone, the first `min(main, total)` descriptors of configuration parameter
34, never the declared total that counts every validator in every shard. The
arithmetic is exact on purpose: the thinnest link on the real chain from the
pinned block carries 66.6712% of its set, 0.0046 percentage points above the
threshold, a margin at which an `f64` comparison would be a coin toss. Below that
threshold the link fails with `BlockError::NotEnoughWeight`.

The signed bytes are rebuilt rather than trusted (`signed_message` in `chain.rs`,
`crates/ton-net-block/src/signature.rs`). Mainnet has used two signed forms, and a
walk that crosses the changeover carries both. The older form signs a block
identity outright. The newer Simplex form signs a finalize vote that names a
candidate only by hash, so on its own it says nothing about which block it is
for; the client reads the candidate that travels with the set and requires it to
name the link's destination, otherwise real signatures lifted from one block
would carry another. The session id is signed alongside the vote, so a signature
raised in one consensus session cannot be replayed into another. A set of any
third form is refused by name as `BlockError::UnknownSignedForm`, never read as
one of these. The ed25519 rule itself is libsodium's
`crypto_sign_verify_detached`, the rule the network uses: canonical `A`, `R`, and
`S`, neither `A` nor `R` of small order, `S` below the group order, and the
equation compared without cofactor slack. Being stricter would refuse a signature
the validators accepted and stall a thin link, so the target is exactly that set.

Two more forgery angles are closed where the weight is summed (`carried_weight`
in `chain.rs`, and set construction in `validators.rs`). A signer outside the set
contributes nothing rather than failing the whole set, so a hostile peer cannot
stall a client by adding one foreign signature. A validator named twice in a
signature set is counted once, and a signature is added to the tally only after
it verifies, so a bad duplicate cannot displace a real one. A set that names the
same key twice is refused when it is read, because a key counted twice would be
paid twice toward the threshold.

Replay is answered by the clock, because nothing inside a proof records when it
was served. A fully signed, genuinely committed block from last year passes every
check above. The block's own generation time against the local clock is the only
freshness signal there is (NET-ADR-005). `fresh_enough` refuses a proven head
older than the configured bound with `Error::Stale`
(`crates/ton-net/src/sync.rs`), the bound defaulting to 600 seconds and settable
through `Config::with_max_head_age`, a bound of zero refusing every head. A block
stamped more than 300 seconds ahead of the local clock is reported as
`Error::ClockBehind` rather than accepted, because the age measurement saturates:
to a clock a year slow, every block from the last year would read as brand new
and the freshness bound would switch itself off. Reporting a wrong clock rather
than obeying it keeps the one anti-replay check from silently failing open. This
is why the local clock is named as the second trusted input alongside the anchor.

## A resource-exhaustion attempt

Sync is the first place a server decides how much work the client does, so the
bounds ship with it rather than as a later hardening pass, and they are read off
the wire before any expensive work runs (NET-ADR-005,
`crates/ton-net/src/sync.rs`). `within_bounds` inspects a reply before the cell
engine parses a proof or the curve arithmetic touches a signature, because
everything it checks is a count or a length that costs nothing to read: at most
64 links per reply, at most 1,048,576 bytes per Merkle proof, at most 1,024
signatures per set. Across a whole sync the `Walk` counter refuses more than
4,096 links or more than 512 replies, and `advanced` refuses a reply that leaves
the anchor where it was, so a server answering forever without progress ends the
sync rather than running it in circles. `worth_continuing` stops a walk that has
itself run longer than the freshness bound, since nothing it could still reach
would pass the freshness check. Each of these ends the sync with a named
`Error::Sync`, and none relaxes a check to let a sync succeed.

One amplifier is specific to signature checking and is bounded where it lives.
Signatures are verified before duplicates are removed, which is the sound order,
but it means a set padded with copies of one member would cost a curve operation
per copy. `carried_weight` spends a per-link budget of twice the set size on
verification attempts, so a set stuffed with duplicates is refused rather than
run (`crates/ton-net-block/src/chain.rs`).

The cell engine carries its own bounds, because a bag of cells arrives from the
same untrusted server and a Merkle proof is attacker-shaped by design
(NET-ADR-010, `crates/ton-net-cell/src/boc.rs`). A parsed cell is roughly 250
bytes of live heap and the smallest one on the wire is two bytes, so without a
bound a bag would expand by two orders of magnitude on the way in. `parse_boc`
refuses a declared cell count past `MAX_CELLS`, which is 131,072, with
`CellError::TooManyCells`, and a reference chain past `MAX_DEPTH`, which is 1,024,
with `CellError::TooDeep`, the depth bound also keeping a deep graph from
overflowing the stack when it is later walked or dropped. The count is checked
against the bytes before anything is allocated for it: the header reader refuses a
count larger than `MAX_CELLS`, then refuses a count whose minimum two bytes per
cell exceed what remains (`CellError::Truncated`), and requires the declared cell
area to account for exactly the bytes left, so a bag cannot claim one length and
carry another (`crates/ton-net-cell/src/boc/header.rs`). A reference that does not
point strictly forward is `CellError::BadReference`, which also rules out cycles.
Underneath all of this the ADNL frame layer refuses a frame body past 16,777,216
bytes before any allocation follows it (`crates/ton-net-adnl/src/frame.rs`),
though the real work bounds are the smaller ones above, set where the work is.

## The trust anchor, the one trusted input

A verifier needs a root: some block held true before anything has been checked,
from which every later fact is derived. That root cannot come from a server,
because a server that supplied it could then invent a chain that verifies cleanly
against it. The root is a single masterchain key block named `init_block` in the
network config, and it is the only value a verified read takes on trust from the
chain's side of the world (NET-ADR-005, `crates/ton-net/src/config.rs`).
Everything else is earned one validator signature set at a time.

The config carries two things whose trust requirements are opposite, and the code
says so at the point a caller might refresh it (`Config::mainnet` documentation).
The liteserver list needs no trust: every answer a server gives is checked against
a proof, so a hostile server can stall or lie and the lie is refused. The
`init_block` is the other case. A fetched one moves this client's root of trust to
whoever served it, after which every proof verifies cleanly against whatever chain
that party invented. Refreshing a server list and moving the anchor are therefore
different decisions, and fetching a config makes the second one whether or not the
caller intends it. A caller who already trusts a block, such as one saved from an
earlier run through `Client::anchor`, hands it in through `Client::connect_from`
and starts the walk from there rather than trusting a fresh fetch.

The anchor is always a key block, never a proved head, because only a key block
carries the validator set that makes the next step checkable (NET-ADR-005). A
sync hands its proved head to the read that wanted it and keeps the last key block
of the walk, so the next sync starts from a block a chain can continue from. That
single rule is what removes backward links from the picture, and a backward link
is refused by name as `BlockError::BackwardLink` rather than read and
half-checked.

The bundled mainnet anchor is a point-in-time snapshot of what the public mainnet
config published, at masterchain sequence number 46894135, not a block this
library chose. Its root hash and file hash are pinned in
`crates/ton-net/src/config.rs` and asserted by a test in that module, and
restated in NET-ADR-005. A first sync walks forward from it, so the further it
recedes the longer that walk runs, which makes refreshing the snapshot release
work rather than routine upkeep. The anchor holds no secret, but it is a root of
trust: anything that can write to wherever a caller stores it can choose what the
client believes. The library stores nothing and picks no location, so that
storage is the caller's own threat-model decision.

## The custody position

The library holds no user key today, and no key path exists in the current code
to hold one. The read path signs nothing, and the only secret it
computes is the ephemeral per-session ADNL key that secures the transport, which
is not the user's and protects nothing of the user's. This is the non-custodial
position of NET-ADR-001, and
the read path realizes it structurally: there is no field, no argument, and no
call that takes a user's private key or seed.

The write path is committed scope and the project's floor (NET-ADR-003), and it
is where key material first enters the picture. It enters through a signer seam:
the caller supplies the signing operation, and the library constructs and
broadcasts the external message around a signature the caller produced, never
holding or seeing a private key or a seed. Constructing and broadcasting a
message is not custody. Signing with a key the library held would be, and the
library will not do that. That line is what lets the write path be in scope
without the library taking control of user funds, and the custody question for
any part of it is settled in a security review before that code is written
(NET-ADR-001, NET-ADR-003). Because the seam is not yet built, this section
records a design commitment rather than a shipped check, and it is noted as such.

The consequence for this threat model is that the adversary here cannot reach a
key by attacking the client, because there is no key on this side to reach. The
attack surface is confined to what the client believes, which the read-path checks
above are built to protect, and the write path is arranged so that the same
confinement holds once it exists: a compromised or hostile server can refuse to
broadcast a message or lie about a result, and the result is checked like any
other read, but it can never obtain the signing key, because the library never
has it.

## Residual trusted inputs and assumptions

Three inputs are trusted by construction, and naming them is part of stating the
model honestly.

- The pinned anchor. One masterchain key block is believed before anything is
  checked. A caller who wants a different root supplies it explicitly, and a
  caller who fetches a fresh config trusts that config's source for the anchor.
- The local clock. It is the only freshness signal a proof cannot provide, so a
  client whose clock is wrong has a weaker replay guarantee than one whose clock
  is right. A clock far enough behind is reported rather than obeyed, so the check
  fails loudly instead of silently switching off.
- The vetted cryptography. The ed25519 verification, the SHA-256 and SHA-512
  digests, and the AES-CTR stream are the single audited copy of each primitive
  the workspace carries (NET-ADR-004). Their correctness is assumed here and
  earned by keeping one copy of each rather than many.

Everything else a client believes is derived from the first of these by
cryptography, refused as a named error when it does not check out, and never
upgraded from a server-reported value to a verified one without the proof that
makes the difference.
