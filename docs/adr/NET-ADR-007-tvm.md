---
id: NET-ADR-007
title: The local TVM, and the differential harness that grades it
status: accepted
date: 2026-07-23
supersedes: none
superseded-by: none
---

# NET-ADR-007: The local TVM, and the differential harness that grades it

## Context

ton-net verifies every answer against validator signatures rather than trusting a server
(NET-ADR-001). A proven read returns an account's code and data as cells proven against a
block, and the type discipline of NET-ADR-003 keeps that proof honest: a `Verified` value has
a private constructor and is a distinct type from a `ServerReported` one, with no operation
that turns the second into the first.

Not every value a caller wants is a stored field. Many are the result of running a get-method
over an account's code and data, a jetton balance being the common case. Today that computed
result can only be server-reported: the account's code and data can be proven, but nothing
local runs the computation, so the answer to a get-method is a server's word and sits outside
the guarantee the rest of the client makes. A proven read establishes the inputs; the
computation over them is still trusted to a server.

NET-ADR-003 puts a local TVM in scope, and NET-ADR-001 fixes that the TVM is what carries the
trust guarantee to computed results and places it last among the large components. This record
fixes the approach: how a local TON Virtual Machine is built so a get-method result becomes
trustless, and how its correctness is graded before any of it is trusted.

The TVM is not built. No `tvm` crate exists in the tree. This record is the decided approach
and the design intent, not a description of present behaviour. Nothing here should be read as
code that runs today.

## Decision

**1. A local TVM runs get-methods against proven code and data, and its result is a distinct
type from a server-reported one.** The TVM takes an account's code and data, proven against a
block, and runs a get-method over them locally. The computed result is surfaced in a result
type in the verified family, distinct from a `ServerReported` value, in the same discipline
NET-ADR-003 fixes and `crates/ton-net/src/verified.rs` realizes for proven reads, inside the
one audited core of NET-ADR-002. A caller cannot mistake a result computed locally over proven
inputs for a server's word, because the two are different types and there is no operation that
turns one into the other. That result type does not exist yet, because the TVM does not exist
yet.

**2. The differential harness comes before the first opcode.** Continuous integration builds a
pinned reference C++ TON emulator, feeds it a case, and compares this implementation's result
against the emulator's for the same case. The harness is the gate the first opcode passes
through, and it is in place before any opcode is written. The emulator is a differential
oracle, the same shape of check that grades signature acceptance against an audited
implementation (NET-ADR-006): this implementation is measured against an established reference
rather than trusted on its own word.

**3. Opcodes land with their differential cases, never ahead of them.** An opcode is added
together with the cases that grade its behaviour against the emulator. An opcode with no case
against the emulator is unproven behaviour on the trust path, and the harness's rule is that it
does not enter the table.

**4. The replay corpus is captured from mainnet and re-derived against the emulator.** The
vectors the TVM replays are taken from real mainnet execution and re-derived against the pinned
emulator, not adopted from elsewhere. A corpus re-derived against the emulator grades this
implementation against the network's own reference; a corpus taken from another source would
grade it against that source's reading of the machine.

**5. Heavy cryptographic primitives come from established libraries.** The pairing curve
BLS12-381 and the secp256k1 curve that the TVM's crypto opcodes need are taken from published,
reviewed crates, not hand-written in this repository, under the dependency policy of
NET-ADR-004. A hand-rolled pairing or curve on the trust path is unaudited code with no
advisory channel. The specific crates enter the tree under NET-ADR-004's single-copy rule when
the opcodes that need them are built.

**6. Each opcode declares its minimum global version, and the table is asserted complete.**
Every opcode records the minimum TVM global version at which it exists, and an inventory test
asserts that the opcode table is complete against that version set, so a missing opcode is a
failing test rather than a silent gap.

**7. The TVM is the last large component.** Sequencing is dependency-first (NET-ADR-001), which
places the write path early and the TVM last among the large components. v1.0.0 is full parity
including the TVM, and the API does not freeze without it.

## Alternatives considered

- **Take get-method results from the server as reported.** Rejected. That leaves every computed
  value outside the guarantee the library exists to make, which is to verify every answer
  rather than trust a server (NET-ADR-001). A jetton balance would stay a server's word while a
  native balance is proven, a split with no principled line. The TVM is what closes it.
- **Hand-write the pairing and the secp curves.** Rejected. A hand-rolled BLS12-381 pairing or
  secp256k1 curve on the trust path is unaudited code with no advisory feed, the same reason
  NET-ADR-004 rejects hand-writing the signature curve. Established crates carry the review and
  the channel; cleverness belongs in the system design, not in the primitives.
- **Write opcodes ahead of their differential cases.** Rejected. An opcode with no case grading
  it against the emulator is behaviour trusted on this implementation's own word, which is the
  trust the differential harness exists to remove. The harness comes first, and each opcode
  lands with the cases that grade it.

## Consequences

- A computed get-method result carries the trust class of a proven read, distinct in the type
  system from a server-reported one, so a caller reads the difference rather than tracking it by
  convention.
- The opcode set grows behind the harness, not ahead of it. No opcode ships without cases that
  agree with the pinned emulator, so a decode or execution defect is a failing differential case
  rather than a wrong answer a caller cannot see.
- The TVM's crypto audit surface is established libraries with advisory feeds, one copy of each
  primitive across the tree (NET-ADR-004), not hand-written code.
- The minimum-global-version declarations and the inventory test make an incomplete opcode table
  a failing test. Completeness against the declared version set is checked, not asserted in
  prose.
- The TVM is the last large component. Until it lands, a computed contract result stays
  server-reported, which is the gap it closes, and v1.0.0 is not reached without it
  (NET-ADR-001).
- This record is design intent. The `tvm` crate does not exist, and no behaviour described here
  runs today; the record fixes the approach so the first opcode is built against a harness that
  already stands.

## Chain scope

TON-specific (NET-ADR-001, NET-ADR-003). The virtual machine, its opcode set, its global-version
arc, and its get-method calling convention are TON's own, and the reference emulator that grades
it is TON's own. Composing several chains lives above ton-net, in the consumer.

## Custody and security

No user keys. The TVM is pure computation over proven inputs: it runs a get-method against code
and data already proven against a block, holds no key, signs nothing, and moves no funds. A
get-method is a read, not a state transition, so running one locally creates no custody or
control over user assets. This record does not change the custody position of NET-ADR-001 and
NET-ADR-003.

The security value is twofold. The result is typed distinct from a server-reported value, so a
computed answer cannot be mistaken for a server's word. The crypto opcodes rest on established,
single-copy primitives with live advisory feeds (NET-ADR-004), so the pairing and curve on the
trust path are reviewed code rather than hand-written.

## Verification

When the TVM is built, its correctness is a standing differential check rather than a claim.

- The differential harness is the gate. Continuous integration builds the pinned reference C++
  TON emulator, and every case in the replay corpus reproduces against it, result for result.
  An opcode's cases must agree with the emulator or the gate fails.
- The corpus is first-party. Its vectors are captured from mainnet and re-derived against the
  pinned emulator, so the suite grades this implementation against the network's own reference,
  not against a reading of the machine adopted from elsewhere.
- The opcode table is asserted complete. Each opcode declares its minimum global version, and
  the inventory test fails on a table that is incomplete against the declared version set.
- The crypto primitives are graded and single-copy. The pairing and secp curves come from
  established crates under NET-ADR-004, checked at the dependency gate for a single copy and a
  live advisory feed.

None of these checks runs today. There is no `tvm` crate in the tree, so this section describes
the gate the first opcode is written against, not a suite that passes now.
