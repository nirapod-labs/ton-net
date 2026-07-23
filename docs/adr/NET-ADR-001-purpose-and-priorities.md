---
id: NET-ADR-001
title: Purpose, and the priorities that follow
status: accepted
date: 2026-07-23
supersedes: none
superseded-by: none
---

# NET-ADR-001: Purpose, and the priorities that follow

## Context

ton-net grew from a TL codec and unverified reads to a trust-minimized read path, and it is
now bringing the cell engine to full capability. What no record stated is what the library is
for, whose need breaks a tie when two consumers pull in opposite directions, how fast it has
to be, and what finished and abandoned mean.

That gap let priority drift. Capabilities were once sorted by whether one consumer needed
them, and the node and indexer scale operations were deferred on that basis, a sort that was
wrong: the surface is not bounded by one caller. This record fixes purpose and the priorities
that follow from it, so a scope question resolves against a decision rather than being
re-argued each time it comes up. It is the ground the other decisions rest on.

## Decision

1. **Purpose.** ton-net is the reference Rust full TON client: one audited core that speaks
   the whole client protocol and verifies every answer against validator signatures rather
   than trusting a server, distributed across language bindings. It is a recognized
   open-source project in its own right, and Nirapod is one consumer of it. Its reasons are
   three and co-equal: evidence of serious engineering, a correct Rust client the TON
   ecosystem can use, and a controllable and verifiable base a wallet can depend on.

2. **Boundary.** Scope reaches everything a program talking to TON needs, and never crosses
   into node or validator territory. Growth means a more complete and more widely adopted
   client, not a move toward becoming network infrastructure. The scope is fixed in
   NET-ADR-003.

3. **Consumer priority.** The library serves every consumer and privileges none by default.
   When needs conflict, the tie breaks toward the most demanding consumer, indexer and node
   scale, because that superset already contains the lighter consumers' needs and the extra
   breadth is carried as isolated, feature-gated paths that cost a lighter consumer nothing
   at runtime. One guard bounds this: the tie-break holds only while it does no harm to the
   wallet path. A scale capability that cannot be built without degrading the client's core,
   the immutable cell type, the mobile binary size, or the simple read-and-build API, is
   escalated rather than taken automatically.

4. **The performance bar.** Correctness and safety are the floor and win any real conflict.
   That ordering is not permission to be slow. The deliverable is correctness and safety
   delivered performantly, all three together. The bar is best-in-class on all three:
   performance is maximized within the safety floor through sound engineering, never through
   unsafe or unauditable shortcuts. A capability that is correct and safe but needlessly slow
   is not finished. Performance within safety is part of every capability's definition of
   done.

5. **Version arc and sequencing.** v1.0.0 is full parity, including the TVM, and the API
   freezes only when the client is genuinely complete. There is no external deadline;
   completeness is preferred over an early version label. Milestones proceed in
   dependency-first order, which already places the write path early and the TVM last among
   the large components. The product spine, the cell engine then the write path, is the
   uninterrupted highest-priority thread.

6. **Relationship to the wider product.** The Nirapod wallet is a soft consumer, free to use
   a different client, so ton-net earns its place on merit and its roadmap is not hostage to
   the wallet. ton-net stays TON-specific; composing several chains is the consumer's
   concern, above ton-net. ton-net releases on its own open-source cadence and a consumer
   pins the version it wants.

7. **Success and failure.** Success is a complete, correct, best-in-class client, audited by
   an internal capability rather than a paid external firm, that Nirapod uses. Real external
   adoption is a valued stretch, not a gate, so the adoption surface stays healthy enough
   that an outside project can adopt without outreach being a core deliverable. Failure is
   abandoning the work below a usable floor. The floor is fixed: the current milestone, the
   cell engine to full capability with every gate green, is the minimum coherent state, and
   the write path, a trust-minimized read-and-send client able to back a wallet end to end,
   is the floor the project holds itself to.

## Alternatives considered

- **Leave purpose implicit.** Rejected. The absence of this record is what let priority drift
  and let a settled scope be re-argued per change.
- **Define ton-net as the wallet's servant.** Rejected. The wallet is a soft consumer and the
  surface is not bounded by one caller.
- **Ship 1.0 as a read and write subset, deferring the TVM to 2.0.** Considered and rejected.
  With no deadline the only argument for it, speed, is absent; the TVM carries the trust
  guarantee to computed results; and deferring the hardest component behind a 1.0 label is
  the reframe this record exists to prevent.
- **Best-effort performance with no bar.** Rejected. A recognized client is benchmarked, and
  correct but slow is half a deliverable.
- **A paid external audit.** Declined. An internal capability performs the audit.

## Consequences

- Priority questions resolve against this record. The node and indexer scale bag operations
  in the current milestone are in scope and built now, to the performance bar.
- The performance bar raises the definition of done for every capability, including those
  already built: a correct but slow path is unfinished.
- The audit is an internal deliverable, aimed at a Rust codebase.
- The floor binds the work: it does not stop before the write path.

## Chain scope

TON-specific (NET-ADR-002). Composing several chains lives above ton-net, in the consumer.

## Custody and security

No user keys today. The write path first touches key material through the signer seam, where
a caller supplies a callback and the library never sees a key; whether any part of that
creates custody is settled before that code is written (NET-ADR-003). This record fixes
purpose and priority and does not change the custody position.

## Verification

- The consumer-priority guard is testable: a scale capability leaves the wallet-facing paths,
  parse, build, and verify, and the immutable cell type unchanged, shown by the existing
  oracles and the isolation of the scale modules.
- The performance bar is measured: criterion benchmarks on the hot paths, and the scale
  operations agree byte for byte with the in-memory path while bounding memory.
- The floor is observable: the cell engine ships every gate green, and the write path sends a
  real transfer observed in a proven account read.
