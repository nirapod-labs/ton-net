---
id: NET-ADR-007
title: Verify ed25519 on the curve crate already in the tree, and match libsodium's acceptance rule
status: proposed
date: 2026-07-21
amends: NET-ADR-003
supersedes: none
superseded-by: none
---

# NET-ADR-007: Verify ed25519 on the curve crate already in the tree, and match libsodium's acceptance rule

## Context

v0.3.0 is the first release that verifies an ed25519 signature. Everything before it
used ed25519 keys without checking a signature: the ADNL handshake converts a key to its
Montgomery form for a Diffie-Hellman exchange, and the proof engine recomputes hashes.
Block sync is different. A forward link is believed because more than two thirds of a
validator set signed the destination, so signature verification moves onto the trust path
and stays there.

That raises a dependency question NET-ADR-003 answered for a narrower case. That ADR sets
two rules: one copy of each crypto crate in the tree, verified with `cargo tree -d`, and
`ed25519-dalek` rejected as a separate dependency because the ADNL key conversion needs
only `curve25519-dalek`. The second rule was decided for key conversion, not for
verification, so it is fair to reopen it now that the thing `ed25519-dalek` exists for is
actually needed.

Reopening it does not help. Checked 2026-07-21, neither current version can be added
without breaking the first rule:

- `ed25519-dalek` 3.0 depends on `curve25519-dalek` 5, which is the version already in
  the tree, but also on `sha2` 0.11. That sits on the `crypto-common` 0.2 generation
  while tl-proto holds the tree at 0.1, so it duplicates `sha2`, `digest`,
  `crypto-common`, and `block-buffer`. This is the exact duplication NET-ADR-003 was
  written to prevent, and that ADR already rejected the newer RustCrypto generation for
  it.
- `ed25519-dalek` 2.2 depends on `curve25519-dalek` 4, duplicating the curve crate
  instead.

There is a second question hiding behind the first, and it turns out to matter more.
ed25519 verifiers disagree on edge cases, and the disagreement is a known source of
consensus divergence between implementations that all consider themselves correct: whether
a small-order public key is refused, whether non-canonical encodings of `R` or `S` are
accepted, and whether the verification equation is cofactored. Picking a library does not
answer that question, because a library's default is its own opinion rather than TON's.

The feasibility spike measured what the answer costs. Walking mainnet's whole proof chain,
the thinnest link carries 66.6712% of its validator set's weight against a two-thirds
threshold: 0.0046 percentage points of headroom, about a two-hundredth of one validator's
weight. Certificates are assembled to just clear the threshold and then stop collecting,
so thin margins are the normal case rather than a rare one.

## Decision

Verify ed25519 signatures on `curve25519-dalek` and `sha2`, both already in the tree, and
add no runtime dependency. Target libsodium's acceptance rule exactly.

1. **No new runtime dependency.** The verification equation is built on the operations
   the curve crate already exposes: a canonical scalar decode, a wide reduction of the
   SHA-512 digest, and the double-scalar multiplication against the basepoint. This
   extends NET-ADR-003's table rather than contradicting it: that ADR already does raw
   curve arithmetic directly for the ADNL handshake, for the same one-curve-crate reason.
2. **The acceptance rule is libsodium's `crypto_sign_verify_detached`**, which is what
   TON validators sign and verify with. That function is the normative reference, not
   this ADR's reading of it: as currently read it requires canonical `A`, `R`, and `S`,
   refuses `A` and `R` of small order, requires `S` below the group order, and compares
   the recomputed `R` without cofactor slack, but the differential test in point 3 is
   what settles the rule rather than this list. The aim is to accept exactly the set
   libsodium accepts, no more and no less.
3. **`ed25519-dalek` is added as a development dependency** and the two implementations
   are compared against each other over random and adversarial inputs. A development
   dependency does not ship, does not enter a consumer's tree, and duplicates nothing a
   consumer builds.
4. **The rule is pinned by vectors**, including the published edge cases for small-order
   keys, non-canonical encodings, and torsion components, which are precisely the inputs
   implementations disagree on.

Point 2 overturns the obvious answer, and the reasoning is worth keeping. The tempting
position is that stricter is safer, because a stricter rule can only refuse a signature
and never wrongly accept one, so its failure mode looks harmless. At 0.0046 percentage
points of headroom it is not harmless: refusing one signature the validators accepted
drops the link below the threshold and the sync stops. Being stricter than the network is
a way to stall, not a free safety margin. Being laxer is worse, so the target is neither
end of the range but the network's own rule.

Aiming at that rule rather than at a library's default also reframes what point 1 gives
up. No off-the-shelf crate offers "exactly what libsodium accepts", so choosing one would
not have discharged the correctness question anyway; it would have moved it into a
default nobody had checked against TON.

## Alternatives considered

- **`ed25519-dalek` 3.0, accepting the `sha2` duplication.** Rejected, and it is the
  fallback if this decision is reversed. It carries two SHA-256 implementations and two
  copies of the digest machinery into every consumer's binary, including the wasm bundle
  the browser binding ships, which is the cost NET-ADR-003 exists to prevent. The
  duplication is waste rather than a correctness risk, so this is a defensible outcome,
  merely a worse one.
- **`ed25519-dalek` 2.2 on `curve25519-dalek` 4.** Rejected. It duplicates the curve
  crate and pins the tree to an older dalek line at the same time.
- **`ed25519-dalek`'s `verify_strict`.** Rejected on the measurement above. It refuses
  small-order `R` and uses the uncofactored equation, which is close to libsodium, but
  adopting a library's notion of strict is adopting an opinion that was not formed
  against TON. The rule needs to be stated and tested, not inherited.
- **`ring` or another C-backed implementation.** Rejected for the reason NET-ADR-003
  already gives: it does not compile cleanly to `wasm32-unknown-unknown`, which
  disqualifies it against the browser binding.
- **Wait for tl-proto to move to the `digest` 0.11 generation, then take
  `ed25519-dalek` 3.0.** Rejected as a plan, kept as a trigger. NET-ADR-003 already names
  that migration as the moment the whole RustCrypto set moves in one step; if it happens,
  taking `ed25519-dalek` costs no duplication and this decision should be revisited on
  its merits. It is not something to block v0.3.0 on.

## Consequences

- The shipped dependency set does not change. `cargo tree -d` stays clean, and the wasm
  bundle carries one copy of each primitive, as NET-ADR-003 requires.
- This project now maintains a signature verification routine on its own trust path.
  That is a fair thing for a reviewer to ask about, and the answer has to be evidence
  rather than assurance: the vectors, the differential test against an audited
  implementation, and the fact that the routine verified 107475 real mainnet validator
  signatures on the spike's cold sync.
- The acceptance rule is written down and testable rather than implicit in a library
  choice, which is the part that most affects whether this client agrees with the
  network.
- A validator who deliberately produced a signature libsodium accepts and this
  implementation refuses could stall a client on a thin link. Matching libsodium is what
  closes that, and any future tightening has to be measured against the margin rather
  than assumed safe.
- Verification runs on public data, so it needs no constant-time guarantee, which is why
  the variable-time double-scalar multiplication is the right primitive and not a
  shortcut.

## Chain scope

Chain-agnostic in mechanism, TON-specific in the rule it targets. Ed25519 verification is
a general primitive; matching libsodium's acceptance rule is a decision about agreeing
with TON's validators.

## Custody and security

No key material is created, held, or used. Verification takes a public key, a message,
and a signature, and returns a boolean.

The security surface is agreement with the network, in both directions. Accepting a
signature TON would refuse weakens the threshold; refusing one TON accepts stalls the
client. The measured 0.0046-point margin is what makes the second failure mode real
rather than theoretical, and it is the reason this ADR fixes the rule instead of leaving
it to a default.

## Verification

- The implementation reproduces the published ed25519 test vectors, including the
  edge-case set covering small-order keys, non-canonical `R` and `S`, and torsion
  components.
- A differential test against `ed25519-dalek` over random and adversarial inputs
  disagrees on nothing, or the disagreement is explained and pinned as a deliberate
  difference from that library's default.
- The cold-sync network test verifies on the order of a hundred thousand real mainnet
  validator signatures without a single valid signature being refused.
- `cargo tree -d` shows no duplicated crypto crate in the shipped graph.
- Confirmed 2026-07-21 in `spikes/sync-feasibility`: 107475 mainnet signatures verified
  on `curve25519-dalek` 5 and `sha2` 0.10, with no new dependency.
