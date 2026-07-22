---
id: NET-ADR-008
title: Scope v1.0.0 as feature parity with tonutils-go at a pinned commit, plus the write path
status: accepted
date: 2026-07-22
supersedes: NET-ADR-002
superseded-by: none
---

# NET-ADR-008: Scope v1.0.0 as feature parity with tonutils-go at a pinned commit, plus the write path

## Context

NET-ADR-002 scoped v1.0.0 as a complete client and excluded the node-only
protocols. Its stated aim was that ton-net would "match or exceed the community's
fullest clients (tonutils-go, pytoniq)". That aim was never measured, and it named
a target that ships weekly, so nothing about it could be checked.

It has now been measured. tonutils-go at commit `749603a` (v1.18.0, MIT) carries
110,109 lines of source outside its examples, against 8,852 in ton-net's core.
Coverage is **8.0 per cent**. Both counts are tracked files only, tests excluded:
`git ls-files '*.go' | grep -v '_test\.go$' | grep -v '^example/' | xargs wc -l`
there, and `crates/*/src` here.

Three findings from that measurement bear on scope.

The first is that NET-ADR-002's exclusions do not survive its own aim. Overlays,
RLDP and QUIC were placed outside v1.0.0 as node-only. tonutils-go ships all
three, at 5,325, 3,519 and 1,408 lines. A scope that excludes them cannot claim to
match the fullest client, so the exclusion and the aim were in contradiction from
the start.

The second is that the write path is absent. `sendMessage` appears in
NET-ADR-002's own in-scope list and in no milestone of the roadmap, and no send
path exists in the tree. tonutils-go carries 4,348 lines of wallet code covering
v1 through v5R1, both highload versions, lockup wallets, seed and hierarchical
derivation, and TON Connect proof checking. A read-only client cannot back a
wallet, which is the product this library exists to serve.

The third is that proof verification is not the differentiator it was assumed to
be. tonutils-go verifies account state, shard membership, transactions, message
queues, and both forward and backward block links, and it walks a proof chain.
What separates ton-net is narrower and sits in the defaults: tonutils-go's default
policy is `ProofCheckPolicyFast`, which its own comment records as "Without master
block checks"; under `ProofCheckPolicySecure` without an explicit
`SetTrustedBlock` it adopts the first block a server sends and logs a warning; and
`GenUtime` appears in its tree only as a struct field, so a genuine chain replayed
from last year passes every check it makes.

## Decision

Scope v1.0.0 as **feature parity with tonutils-go at commit `749603a`, plus full
wallet support**, across the Rust core and the Node binding.

Parity is measured against that pinned commit and no other. Upstream ships weekly;
a target that moves is not a gate that can pass. Later commits are a separate,
later decision.

In scope for v1.0.0, added to what NET-ADR-002 already listed:

1. **RLDP**, including the RaptorQ transfer layer, previously deferred.
2. **Overlays**, previously deferred.
3. **QUIC transport**, previously unlisted.
4. **The write path**: external message construction, `sendMessage` with
   confirmation waiting, and transaction subscription.
5. **Wallets**: v1 through v5R1, highload v2 and v3, lockup, seed phrases and
   hierarchical derivation, and TON Connect proof verification.
6. **The cell engine at full capability**: builders, slices, the five dictionary
   variants, augmented dictionaries, usage trees, virtualization, and Merkle proof
   *creation* rather than verification alone.
7. **The full TL-B type set**, not the subset a proof walk needs.
8. **Contract helpers**: NFT, jetton and TON DNS.
9. **A toncenter HTTP client**, as the fallback path for a consumer that cannot
   reach a liteserver.
10. **A connection pool**: multiple liteservers, sticky contexts, balancing, node
    exclusion, liveness pings and failover.

What does not change is the trust posture, and it is the reason this library
exists rather than a translation of one that already does. Parity is a floor on
capability, never a licence to copy a default:

- The anchor comes from the network config's pinned key block and is never taken
  from what a server offers first (NET-ADR-006).
- `Verified<T>` has a private constructor and cannot be forged; `ServerReported<T>`
  is a different type. A caller cannot confuse them.
- A proven head older than the configured bound is refused rather than reported.
- The crates that decode bytes from an unvouched peer deny `unwrap`, `panic`,
  `unreachable` and slice indexing.

## Alternatives considered

- **Keep NET-ADR-002 unchanged.** Rejected. It excludes protocols its own stated
  aim requires, and it omits the write path while listing `sendMessage` in scope.
- **Narrow v1.0.0 to what a wallet needs** (trust-minimized read and send, core
  plus Node, TVM and the remaining bindings deferred). This was the recommendation
  the measurement supported, and it was considered and declined. It would ship a
  usable client in months rather than years, at the cost of the completeness bar.
- **Track tonutils-go's head rather than a pinned commit.** Rejected. Parity
  against a project that tags weekly is unfalsifiable; the gate would never close.
- **Port tonutils-go to Rust.** Rejected, and separately from the scope question.
  The licence permits it, but a transliteration of a garbage-collected pointer
  graph produces poor Rust, and it would import the defaults listed above. Its test
  corpora and its differential-testing technique are worth taking; its code is not.
  NET-ADR-010 records this for the TVM, where the question is sharpest.

## Consequences

- The work is roughly 101,000 lines of Rust core after the savings the Rust
  cryptographic crates provide, and roughly 300,000 lines including tests at the
  ratio tonutils-go holds. That is 20 to 25 times what has been built to v0.3.0.
- The binding plan cannot survive this scope unchanged. Five binding surfaces
  multiply every core addition, and tonutils-go reached 110,109 lines with no
  bindings at all. NET-ADR-009 resequences them.
- The TVM's cost is now measured rather than estimated, and its approach changes
  accordingly. NET-ADR-010 records it.
- Wallet support puts key material in the library's reach for the first time, and
  whether any of it creates custody is settled before the code is written.
  tonutils-go exposes a signer callback alongside its private-key constructor, so
  parity does not by itself force key custody, and the seam is the shape to match.
- The cell engine becomes the critical path. At 2,138 lines against 20,392 it is
  the smallest fraction of the target, and the wallet, the full TL-B set and the
  TVM each depend on it. Nothing else can start first.
- Milestones grow past v0.9.0. The roadmap uses two-digit minors and reaches
  v1.0.0 when the parity gate closes against the pin.

## Chain scope

TON-specific (see NET-ADR-001).

## Custody and security

The library holds no user keys today. Wallet support changes what is possible, not
what is decided: the signer seam is the primary construction, so a caller supplies
a callback and the library never sees key material. Seed phrase and derivation
support does touch key material and is the part that has to be examined before
it is written.

Parity is a capability bar and never a behavioural one. No default in this library
is adopted from another because that library ships it, and the four trust
properties listed under Decision are invariants, not preferences.

## Verification

- The coverage figure is re-measured against the pinned commit at each release by
  the command recorded above, so it stays a measurement rather than a claim.
- Each milestone's gate names the packages it brings to parity and the line counts
  it closes.
- The four trust properties are covered by tests that fail if a default moves: the
  anchor test refuses a server-offered head, the freshness test refuses a stale
  proven head, and `Verified<T>` cannot be constructed outside the crate.
