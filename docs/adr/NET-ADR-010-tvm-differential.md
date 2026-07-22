---
id: NET-ADR-010
title: Write the TVM against a differential harness, and import the reference corpus rather than the code
status: accepted
date: 2026-07-22
supersedes: NET-ADR-005
superseded-by: none
---

# NET-ADR-010: Write the TVM against a differential harness, and import the reference corpus rather than the code

## Context

NET-ADR-005 decided to include a TVM and to prefer adapting an existing
permissively licensed Rust one, contingent on a validation gate. It recorded that
candidates existed in the Everscale and TON-fork lineages, that none had been
confirmed byte-exact against TON mainnet semantics, and that the Everscale virtual
machine had diverged from TON's over time. It named the fallback, a port of the
reference C++ semantics, as the larger effort.

Surveying what it takes to finish one changes the shape of the decision rather than
only its size.

The expense is not writing the virtual machine. It is proving the virtual machine
matches. In implementations that have got there, the opcode test corpus runs to
roughly twice the opcode source, and almost all of it is differential: the same
input through the reference emulator, and the results compared. A TVM without that
harness is not a cheaper TVM, it is an unvalidated one, and an unvalidated TVM
computing a balance differently from the network is worse than returning the
server's answer and saying so.

That also means the validation is owed whichever route is taken. Adapting an
existing implementation saves the part that is cheap and owes the part that costs,
over code whose divergences from TON are unknown.

## Decision

Write the TVM in Rust, against a differential harness from the first opcode rather
than after the last one.

**The harness comes first.** Before any opcode is implemented, CI can build a
pinned C++ emulator, feed it a case, and compare the result against the Rust
implementation. Opcodes land with their differential cases, never ahead of them.
This inverts NET-ADR-005's ordering, which treated conformance as a gate at the
end of the milestone.

**Capture the corpus, do not inherit it.** The replay cases are taken from mainnet
and their expected values derived against the reference emulator. A corpus is only
worth what its oracle is, and the emulator is the oracle either way, so borrowing
one would still leave every value to re-derive.

**Do not adapt an existing Rust TVM.** NET-ADR-005 preferred adaptation, and the
measurement removes its premise. The saving adaptation offers is in the part that
is cheap, and the validation that costs is owed either way. An adapted virtual
machine whose divergences are unknown has to be differentially tested against the
C++ emulator opcode by opcode, which is the same harness and the same corpus,
against code nobody in this project wrote.

**Use audited cryptographic crates rather than writing the primitives.** `blst`
and the libsecp256k1 bindings carry far more scrutiny than anything written here
would. For a library whose claim is verification, the provenance of the pairing
code is part of the claim.

**Gate opcodes on the TVM global version.** Each opcode declares its minimum
`global_version`, the supported range is published in the support manifest
(NET-ADR-009, Axis 3), and an inventory test asserts no opcode is missing from the
table. Running an old block requires old semantics, so the range is a
compatibility matrix rather than a single number.

**Keep the trust boundary the TVM sits behind.** It is fed proven code, proven
data and proven configuration, and a locally executed result is a distinct type
from a `runSmcMethod` response, as NET-ADR-005 required. That part of NET-ADR-005
is carried forward unchanged.

## Alternatives considered

- **Adapt an existing Rust TVM, as NET-ADR-005 preferred.** Rejected. Adaptation
  saves the cheap half and owes the expensive half, over code whose divergences
  from TON are unknown and, for the Everscale lineage, known to exist.
- **Defer the TVM past v1.0.0.** Rejected under NET-ADR-008. Without it a
  get-method result is the server's word, which is the largest remaining hole in an
  otherwise verified client.
- **Write the TVM first and validate at the end.** Rejected. It is how a virtual
  machine reaches "almost correct" and stays there, because the failures that
  matter are in opcodes nobody thought to write a case for. The harness only finds
  those if it runs from the start.
- **Vendor the cryptographic primitives for control.** Rejected. Control over a
  pairing implementation is not an asset this project wants; a reviewed
  implementation is.
- **Translate an implementation from another language.** Rejected. A
  garbage-collected pointer graph and a dynamically typed stack become poor Rust,
  and the provenance of a security library's hot path should be its own.

## Consequences

- The TVM milestone starts with infrastructure, not opcodes, and shows no
  user-visible progress until the harness runs. That is the correct shape and it
  should be planned for rather than discovered.
- CI gains a C++ toolchain and a pinned emulator build. It is the heaviest job in
  the pipeline and it is on the critical path for the milestone.
- The cell engine must reach full capability first. The virtual machine runs on
  builders, slices, dictionaries and virtualization the cell crate does not have.
- Opcodes are cheap to add once the harness exists, which makes the milestone's
  progress measurable in a way the previous plan's single end gate did not.

## Chain scope

TON-specific (see NET-ADR-001). The differential-harness discipline is
chain-agnostic and applies to any reimplementation of a consensus-critical
execution engine.

## Custody and security

The TVM executes untrusted contract code over proven state. It runs with bounded
gas, and it decodes bytes chosen by a contract author, so it falls under the
crate-level lints that deny `unwrap`, `panic`, `unreachable` and slice indexing.
A locally executed result is a distinct type from a server-reported one, so a
caller cannot mistake a computed answer for a trusted one.

## Verification

- The differential harness runs before the first opcode merges, and every opcode
  merges with its cases.
- The captured corpus replays against the Rust implementation and the emulator and
  the results agree.
- An inventory test asserts every opcode declares a minimum global version.
- The published support manifest names the supported `global_version` range, and
  it is checked against the opcode table rather than written by hand.
