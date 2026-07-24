---
id: NET-ADR-008
title: Versioning, the verification epoch, and the binding sequence
status: accepted
date: 2026-07-23
supersedes: none
superseded-by: none
---

# NET-ADR-008: Versioning, the verification epoch, and the binding sequence

## Context

ton-net is one audited Rust core distributed across language bindings (NET-ADR-002). It
releases on its own open-source cadence, and a consumer pins the version it wants
(NET-ADR-001). One library is many published artifacts: six Rust crates, a binding crate,
an npm package, and a per-platform package for every target the binding builds. Left to
version on their own they drift, and a consumer cannot name the combination it depends on.

Three questions follow, and this record settles them.

The first is how those artifacts are versioned so that one library reads as one thing.

The second is how a caller of a verifier learns that an upgrade changed what the library
accepts as proven. A version answers API compatibility. It cannot answer this, because the
accept and reject boundary moves independently of the API and of any signature: it can move
while every signature stays byte-identical, and it can stay fixed across a breaking API
change. A caller that stored a result marked verified cannot tell, from the version alone,
whether a newer build would still accept it.

The third is the order in which the core reaches other languages. Each binding is a consumer
of the core API. Standing up several before the API has settled multiplies every core change
across that many mapping layers, most of them revised for a decision not yet made.

## Decision

1. **One version, in lockstep.** Every workspace crate carries a single SemVer version
   through workspace inheritance. The version today is 0.3.0. It is declared once, in the
   workspace package table, and each crate takes it with `version.workspace = true`: the six
   library crates (`ton-net-tl`, `ton-net-cell`, `ton-net-block`, `ton-net-adnl`,
   `ton-net-lite`, `ton-net`) and the Node binding crate (`ton-net-node`). The internal
   dependency edges pin the same version, so a crate only ever resolves against its own
   generation. There is one changelog for the library, not one per crate.

2. **One version, mapped per registry.** crates.io carries the six library crates. The Node
   binding reaches consumers through npm, as the `ton-net` package and seven per-platform
   packages under the `@nirapod-labs` scope, one per target the binding builds, each at the
   same version and pinned exact as optional dependencies so the loader installs the single
   native binary the host can run. The binding crate carries the library version like the
   rest but does not publish to crates.io (`publish = false`); its registry is npm. A release
   is tagged `v{version}`. `v0.3.0` is the first published version; `v0.1.0` and `v0.2.0` are
   tags that were never published to a registry. release-plz owns the mechanism: it decides
   the bump, opens the release pull request, tags, and publishes, and it refuses a release
   whose public API moved in a way the bump does not admit.

3. **A verification epoch, separate from the version.** `VERIFY_EPOCH` is a monotonic
   integer, 1 today, that answers the question the version cannot. It rises only when the
   accept and reject boundary moves: when a new kind of proof is accepted, when an acceptance
   condition tightens or loosens, when the rule for validator signature weight changes, or
   when a freshness default changes. It does not move for wording, for performance, or for
   anything a caller cannot observe in an accept or a reject. A caller that stored the epoch a
   result was verified under compares it against the current value and re-verifies when the
   current value is higher, rather than trusting a result an older set of rules produced. The
   number only increases, it is meaningless across libraries, and it is not a version. Each
   rise is recorded in the changelog as the delta in what is now accepted and what is now
   refused. The boundary is pinned in the core as a transcript: the public verifier is run
   over one captured read and ten edits of it, the verdicts are compared against a fixed text,
   and the epoch is that text's first line, so the number and the boundary it names move
   together or the build fails.

4. **Node first, the rest after parity.** The core reaches parity carrying one binding, Node.
   One real consumer of the API is the cheapest design review the API can get, and it is
   enough. Five bindings maintained before the API settles would multiply every core change
   across five mapping layers for no added signal. The browser, Python, Swift, and Kotlin
   bindings follow after the core reaches parity. Every binding stays thin (NET-ADR-002): it
   maps values across the boundary and forwards to the facade, holds no protocol logic and no
   verification, and takes its error codes and its epoch from the core. A follow-on binding is
   therefore bounded work and inherits every check the core already has.

5. **What a breaking change is.** Three things break, and any one of them forces a breaking
   release. An API break is a change a consumer sees in the observable surface, and the
   release process refuses a release that makes one under a bump that does not admit it. A
   behavioral break is a move in the accept and reject boundary, where something that verified
   now fails or something refused now passes; this is the change the epoch tracks, and it is
   breaking whether or not the API moved with it. A wire break is a change in the bytes
   exchanged with the network. SemVer here is measured against the observable API and the wire
   behavior, so a proof-verification change is breaking and an internal refactor is not.
   Before 1.0.0 a minor release is breaking in every ecosystem this ships to: under Cargo the
   leftmost non-zero field carries the break, and under npm a caret range on a `0.x` version
   does not cross the next minor, so `0.2.0` to `0.3.0` is a breaking upgrade a consumer opts
   into.

## Alternatives considered

- **Version each crate on its own.** Rejected. The crates are one library released together.
  Independent versions drift, force a consumer to work out which combination is coherent, and
  produce six near-identical changelogs where none is the one a reader wants.
- **Generate the changelog from commit subjects.** Rejected. A commit subject reads "check a
  block proof chain" and tells a reader upgrading nothing about exposure. The entry that earns
  its place says three proof-verification failures composed into a server that could hand over
  forged state as verified, and no subject carries that. The changelog is written, and the
  same review that approves the release approves it.
- **One number for both the API and the acceptance boundary.** Rejected. The boundary moves
  while the API stays fixed and stays fixed across an API break, so a single number cannot
  answer both. The question a verifier's caller actually has is whether the accepted set
  changed, which an API version never tracked.
- **Stand up all the bindings at once.** Rejected. Before the API settles, five mapping layers
  turn each core change into five, and one real consumer already exercises the surface as a
  design review. The core reaches parity first, and the rest follow.
- **Pin the epoch boundary with a digest rather than a transcript.** Rejected. A digest reports
  that something changed. A transcript reports which case changed and to what, which is what a
  reader needs at the moment the test fails, at the cost of a few hundred bytes of test source.
- **Ship the core as a Rust library only and let each consumer write its own binding.**
  Rejected. The adoption surface, the bindings included, is a maintained deliverable
  (NET-ADR-001, NET-ADR-002), so the bindings are owned and kept thin by rule rather than
  reinvented per consumer and gotten wrong.

## Consequences

- One number identifies the library. A consumer pins one version and gets a known set of
  crates and packages that resolve only against each other.
- A published version is immutable in both registries. A crates.io release and an npm release
  cannot be replaced, so what ships under a version, the third-party notices and the epoch
  among it, has to be right at publish rather than corrected after.
- A stored verified result can age honestly. A caller that kept the epoch can tell when a newer
  build accepts a different set and re-check; without the epoch a cached verified result
  silently outlives the rules that produced it.
- An accidental breaking change fails the release rather than surprising a consumer, because
  the API check gates the bump.
- Reaching a new language is bounded work. A binding inherits every read and every check and
  can weaken none, so the cost is type mapping, not re-verification (NET-ADR-002).
- Before 1.0.0 every minor can break, so a consumer pins to a minor and upgrades on purpose.

## Chain scope

TON-specific (NET-ADR-001). The version stamps a TON client, and the epoch names what that
client accepts as proven against TON validator signatures. Composing several chains lives
above ton-net, in the consumer, and carries its own versioning.

## Custody and security

No user keys and no funds (NET-ADR-001). Versioning stamps artifacts and moves nothing. The
security-relevant piece is the epoch: it is what keeps a stored verified result honest across
an upgrade, so a result checked under an older accept and reject boundary is re-checked rather
than trusted once the boundary has moved. The transcript pins that boundary in the build, so a
change to what verifies fails a test rather than shipping unnoticed under an unchanged number,
and the binding reports the core's epoch rather than one of its own, so no language surface can
claim a boundary the core does not stand behind.

## Verification

- The lockstep is observable in the tree. One version sits in the workspace package table,
  every crate takes it by inheritance, the internal dependency edges pin the same version, and
  the npm package and its seven per-platform packages carry it and pin it exact.
- The API check runs in the release process, so a public-API move under an inadmissible bump
  stops the release rather than reaching a registry.
- The epoch transcript test fails the build when what the verifier accepts changes without the
  number moving, and because the epoch is the transcript's first line, moving one without the
  other fails too.
- The binding reports the core's epoch. `verifyEpoch()` forwards `VERIFY_EPOCH`, so a binding
  cannot report a boundary different from the core's.
- Each epoch rise is recorded in the changelog as the accept and refuse delta, so an upgrade
  that moved the boundary says so in the one place a consumer reads before upgrading.
