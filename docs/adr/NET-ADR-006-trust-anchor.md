---
id: NET-ADR-006
title: Take the trust anchor from the network config's pinned key block
status: proposed
date: 2026-07-21
supersedes: none
superseded-by: none
---

# NET-ADR-006: Take the trust anchor from the network config's pinned key block

## Context

v0.2.0 gave a read a proof and an anchor: an account is checked against a masterchain
block hash the caller supplies, and a tampered proof is refused. That reduced trust to
one input without removing it, and the remaining input is the awkward one. A caller who
obtains the anchor from the same liteserver they are checking has proved only that the
server agrees with itself. The `Verified<T>` type names the anchor so the limit is
legible rather than hidden, and the roadmap holds the library at a pre-release until it
is closed.

Closing it is block sync. A masterchain key block carries the network configuration in
its own body, including the validator set for the round that follows, so a client
holding one key block can check the signatures on the next and walk forward. Repeating
that from some starting block to the present produces a current block the client has
established for itself, which is exactly the input the v0.2.0 proof engine wants. The
proof engine does not change; it stops being fed by the caller.

A walk needs a place to start, and no cryptography removes that. Something is trusted
first. The decision is what that something is, how visible it is, and whether a caller
who distrusts it has a way out. Everything else in this ADR follows from wanting that
one input to be small, inspectable, replaceable, and published by a party the caller
has already chosen to rely on for something else.

The mechanism is not a matter of opinion, and where the record below states a protocol
fact it was measured rather than read. A feasibility spike walked mainnet's entire proof
chain on 2026-07-21, from the config's pinned block at masterchain sequence number
46894135 to the head at 81057314, a span of 460 days: 78 round trips, 1242 key blocks,
107475 signatures verified, 607 validator-set rotations crossed, 52.6 MB, 154 seconds.
The findings that shape this decision are cited where they are used.

## Decision

Establish the trust anchor by walking key blocks from a single pinned block, and take
that pinned block from the network config.

1. **The anchor starts at the config's `validator.init_block`.** The TON config format
   already carries it, published by the same source, in the same file, as the liteserver
   list a client is already relying on. The library invents no constant of its own.
2. **A caller may start from their own key block instead.** A block identity goes in at
   connect time and comes back out afterwards, so a caller with a block they proved
   earlier, or one they trust for their own reasons, is never forced through the
   config's.
3. **The anchor a client keeps is always a key block.** The head a read is performed at
   is proven for that read and then discarded.
4. **The library stores nothing.** It writes no file, picks no location, and offers no
   storage abstraction. A block identity is a value in and a value out.
5. **Forward links only.** A backward link in a reply is refused with an error naming
   it, rather than skipped or misread.
6. **The masterchain validator set is the first `min(main, total)` entries of
   configuration parameter 34, with their weights unchanged.** The accepted signers and
   the weight in the denominator are read from that one set and never from different
   ones. The seeded shuffle and the `gen_validator_list_hash_short` cross-check are not
   implemented.
7. **A set carries a block when its weight is strictly more than two thirds, in integer
   arithmetic**: `weight * 3 > total_weight * 2`. A signer outside the set contributes
   nothing rather than failing the set; a signer counted twice contributes once.
8. **Both signed forms are supported, and an unrecognised third fails by name.** Mainnet
   uses `ton.blockId` up to masterchain block 59379986 and a Simplex consensus vote from
   that block on, so a client speaking one form cannot reach the head from the config's
   pinned block.
9. **Freshness is a comparison of the proven head's generation time against the local
   clock**, with the bound exposed to the caller and defaulted.

Point 6 carries the load-bearing argument, because it is where a light client most
easily goes quietly wrong. The reference implementation may permute the head of the
list with a seeded generator, but the permutation is over exactly those entries: it
changes the order and changes neither which keys are in the set nor what each one
weighs. Signature checking asks only whether a signer is in the set and what that signer
weighs, so the permutation cannot change any outcome, and the only check that depends on
order is the list hash. Skipping it is safe because deriving the subset wrongly fails
loudly instead of quietly, given that the accepted signers and the denominator come from
the same set: too many validators puts the threshold out of reach, too few discards
honest signatures, and either way live blocks stop verifying. The spike is the evidence.
Mainnet runs about 100 main out of about 380 total, and across 107475 signatures not one
signer fell outside the head-of-list subset; a wrong subset would have left roughly three
quarters of them unrecognised.

Point 7's insistence on integer arithmetic is not fastidiousness. The thinnest link on
the real chain carries 66.6712% of its set's weight, which is 0.0046 percentage points
above the threshold, or about a two-hundredth of one validator's weight. At that margin
a comparison in floating point is a coin toss and `>=` in place of `>` is a different
protocol.

One check that looks obvious is deliberately absent. A validator set names the window it
is valid for, and requiring a destination block's generation time to fall inside the
source set's window is the natural-looking guard. It is wrong: the key block announcing a
rotation is stamped one second past the outgoing set's `utime_until` and is signed by
that outgoing set, so the guard would refuse the first link of every rotation, and a full
sync crosses 607 of them. The set to use is the one the source key block names.

## Alternatives considered

- **Ship a checkpoint constant in the library.** Rejected. It makes this library the
  root of trust for every consumer, in a place a consumer is unlikely to look and cannot
  replace without forking. A recent checkpoint would make a cold sync far cheaper, which
  is a real benefit, and it is the option to revisit if the measured cost proves
  unacceptable; it would need its own ADR, because it reintroduces the input this
  milestone exists to remove.
- **Walk from the zero state instead.** Rejected. The zero state sits in the same config
  file as the pinned block and is published by the same party, so starting there trusts
  nobody less while adding years of key blocks to every cold sync.
- **Keep the caller-supplied anchor as the only option.** Rejected. That is the hole
  v0.3.0 exists to close, and it is why v0.1.0 and v0.2.0 could not be ordinary releases.
- **A `TrustStore` trait, with a file-backed default.** Rejected. A saved anchor is a
  root of trust: whatever can write to where it is kept chooses what the next client
  believes. A library that picks the location picks a threat model on the caller's
  behalf, and a wallet keeping it in an attacker-writable cache directory is a worse
  outcome than any convenience it buys. A trait also does not cross a binding boundary,
  where a block identity crosses as a plain value, so the abstraction would exist only in
  Rust. Revisit if callers ask for it.
- **Anchor on the last block read rather than the last key block.** Rejected. Only a key
  block carries a validator set, so an anchor that is not one has to reach the preceding
  key block by a backward link, which needs the masterchain state and its record of
  previous blocks. Keeping the anchor on key blocks removes that whole path, and the
  spike saw no backward link in 1242.
- **Support only the Simplex form and require a recent anchor.** Rejected. It makes the
  config's own pinned block unusable, which is the entire decision above. The older form
  is the first thing to drop once the published pinned block moves past the changeover.
- **Query several liteservers and require them to agree.** Deferred, not rejected. It
  addresses a real gap that proofs cannot: a single server can stall or withhold, and
  agreement between independent servers is the only thing that catches it. Out of scope
  for this milestone, and worth its own ADR when it lands.

## Consequences

- A read is trust-minimized end to end. The trusted input is one block identity, in a
  file the caller chose, replaceable by a value the caller passes in.
- A cold sync costs a measured 52.6 MB and 154 seconds, and grows by about 800 key blocks
  a year while the published pinned block stands still. Refreshing the bundled config
  snapshot becomes part of cutting a release rather than housekeeping.
- The cost is paid at connect, where a caller expects setup cost, rather than inside a
  read. A caller who does not persist the returned anchor pays it again on every start,
  which the documentation has to say plainly.
- Supporting two signed forms is not optional, and a third arriving is likely: one
  arrived inside the span this milestone has to cross. Refusing an unknown form by name
  makes that a clean failure that tells a caller the library is behind the network,
  rather than a wrong answer.
- A liteserver can still stall, withhold, or serve a real but old head. Nothing here lets
  it forge. Staleness is caught only by the local clock, so a client with a wrong clock
  has a weaker freshness guarantee, and this is stated rather than glossed.
- The v0.2.0 proof engine is untouched. That it needed no change is evidence its seam was
  drawn in the right place.

## Chain scope

TON-specific (see NET-ADR-001). Key blocks, the validator set in configuration parameter
34, and the block-proof link protocol are TON's.

## Custody and security

This library holds no key material, signs nothing, and moves nothing. Block sync is
verification only, over public data, with no secret in the process.

The security surface is real and worth naming precisely. The anchor is the root of trust:
everything a client believes is derived from it, so an attacker who can choose the anchor
chooses the answers. That is the reason the library stores nothing and hands the value
back instead, and the reason the API documentation for the anchor says so rather than
presenting it as an optimisation. The second surface is the sync loop itself, which is
the first place in this library where a server decides how much work the client does; it
is bounded in links per reply, links per sync, proof bytes, and signatures per set, and a
reply that does not advance the anchor ends the sync rather than looping.

## Verification

- A cold sync from the config's pinned block reaches the current head on mainnet, across
  at least one validator-set rotation, proven by the validator sets on either side
  differing rather than by assuming a long enough walk crossed one.
- A warm sync from the resulting key block is a small number of links.
- A tamper corpus over a captured chain is refused, each member with the error the test
  names: a forged signature, a signer outside the set, a duplicated signer, an altered
  weight, a removed link, transposed links, an inverted direction flag, an inverted
  key-block flag, and a chain stopping short of its target.
- The weight comparison is tested on both sides of the boundary, with a set at exactly
  two thirds refused.
- Both signed forms verify against hermetic fixtures, and an unrecognised third fails
  with a message naming it.
- A sync terminates on any sequence of replies, including an adversarial one, within the
  stated bounds, and a stale head is refused.
- Measured on mainnet 2026-07-21: 1242 links, 107475 signatures, 607 rotations, no
  backward link, no signer outside the head-of-list subset.
