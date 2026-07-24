---
id: NET-ADR-006
title: "Validator signature verification: the signed form and the two-thirds rule"
status: accepted
date: 2026-07-23
supersedes: none
superseded-by: none
---

# NET-ADR-006: Validator signature verification: the signed form and the two-thirds rule

## Context

NET-ADR-005 fixes the trust anchor: a pinned key block, and a sync that walks forward from it
one signed link at a time. That decision leaves one question to this record: how a single
block is believed. A liteserver answers `getBlockProof` with a run of links, the server picks
the route, and the client believes nothing about it. Every field of every link is a claim
until something checks it.

A link is worth nothing without its signatures. A block's file hash is the one field of its
identity no Merkle proof can establish, being a hash of the serialized block file rather than
of the cell tree. The header proof establishes what a block says about itself; the signatures
establish that it is the block the network committed. So a destination is believed only once
more than two thirds of the source key block's validator set has signed for it.

Three things have to be right for that sentence to mean anything, and each is a place a light
client goes subtly wrong: which set signs, what the signatures cover, and the weight rule that
decides. This record fixes all three against the code and against captured mainnet data, so
none of it is an assumption.

## Decision

1. **The validator set is derived from configuration parameter 34 of the source key block.**
   The masterchain signing set, the one that may sign a masterchain block, is the first
   `min(main, total)` descriptors of parameter 34's list, with their weights unchanged. The
   code names the parameter `CURRENT_VALIDATORS = 34` and reads the count of `total`
   validators, the count of `main`, and the per-index descriptor dictionary out of it. It
   requires `main` to be nonzero and at most `total`. Parameters 32 and 36, the previous and
   next sets, are not read: a link is checked against the set its own source key block names.

2. **The seeded shuffle and the `gen_validator_list_hash_short` cross-check are not
   implemented.** Signature checking asks a set two questions, is this signer in it and what
   does it weigh, and neither answer depends on order. The shuffle only reorders the same
   entries and changes no key and no weight, and the hash cross-check is the only check that
   depends on order. Skipping the cross-check is safe under one rule the code holds to: the
   accepted signers and the weight in the threshold's denominator come from the same set.
   Under that rule a set derived wrong fails loudly, taking too many validators makes the
   threshold unreachable and taking too few discards honest signatures, and either way live
   mainnet blocks stop verifying.

3. **A block is accepted only when the verified weight is strictly more than two thirds of the
   set's own total weight.** The predicate is exact integer arithmetic, promoted to `u128` so
   the multiplication cannot wrap:

   ```
   carries(weight)  =  u128::from(weight) * 3  >  u128::from(total_weight) * 2
   ```

   Strictly greater, with no rounding and no floating point. Exactly two thirds does not carry;
   the first integer above it does. The denominator `total_weight` is summed over the
   masterchain subset alone, not the 64-bit total the parameter declares, which counts every
   validator in every shard and is read past. The code records why the arithmetic is exact:
   the thinnest link on the real chain from the block the mainnet config pins carries 66.6712%
   of its set, 0.0046 percentage points above the threshold, a margin at which an `f64`
   comparison is a coin toss.

4. **Each validator is counted once, and only after its signature verifies.** Two guards, in
   two places. When the set is read, a key that appears twice is a refusal rather than
   something to deduplicate, because a key counted twice would be paid twice towards the
   threshold. When weight is summed over a signature set, a repeated signer contributes once,
   and a signature is added to the tally only after it verifies, so a bad duplicate cannot
   displace the real one and drop a link below the threshold. Verifying before deduplicating
   is the sound order but lets a set padded with copies of one member cost a curve operation
   per copy, so the work is bounded to twice the set size.

5. **A signer outside the set contributes nothing rather than failing the whole set.** A
   signature from a validator of another round is ordinary junk inside a set, and a hostile
   peer could otherwise stall a client by adding one. The set is refused only when the weight
   that does verify falls short of the threshold.

6. **The signed form is one of two, and the exact bytes are the ones TON's validators sign.**
   A signature says nothing about what was signed, so the client rebuilds the exact message
   and checks against it. Mainnet has used two forms and changed form at masterchain block
   59379986; a walk that crosses that point carries both.

   ```
   Ordinary form (older), 68 bytes on the wire:
     BlockId { root_cell_hash = to.root_hash, file_hash = to.file_hash }
     bytes: 0xc50b6e70 (little-endian constructor id) ++ root_hash[32] ++ file_hash[32]

   Simplex form (newer):
     DataToSign {                                       constructor 0xa8e33df8
       session_id[32],
       data = Vote::Finalize {                          constructor 0x40a7e105
         CandidateId { slot, hash }                     constructor 0xb691cd3f
       }
     }
     where hash = SHA-256(candidate), and candidate is a consensus.CandidateHashData
     naming the destination block (Ordinary 0xe8f9bcdc or Empty 0x72b4d933).
   ```

   The older form signs a block identity outright. The Simplex form signs a finalize vote that
   names a candidate only by hash, so on its own it says nothing about which block it is for.
   The client reads the candidate that travels with the set and requires it to name the link's
   destination, otherwise real signatures lifted from one block would carry another. The
   session id is signed alongside the vote, so a signature raised in one consensus session
   cannot be replayed into another. Both candidate constructors are accepted: an empty slot's
   finalize votes certify the block the slot extends, because Simplex finalization is
   transitive. A signature set of any third form is refused by name, never read as one of these.

7. **The ed25519 rule is libsodium's `crypto_sign_verify_detached`, the rule the network
   itself uses, not something stricter.** A signature is accepted exactly when `A`, `R`, and
   `S` are canonically encoded, neither `A` nor `R` is of small order, `S` is below the group
   order `L`, and `k * (-A) + s * B == R` holds with the equation compared without cofactor
   slack, where `k = SHA-512(R || A || message)` reduced modulo `L`. Canonical encoding is
   enforced by decompressing a point and requiring it to re-compress to the same bytes; `S < L`
   is enforced by a canonical scalar decode. A non-verifying signature returns `false`, not an
   error, because within a set it is an ordinary outcome. The verification is variable-time by
   design, since the key, the message, and the signature are all public. Being stricter than
   the network is not a free margin here: refusing one signature the validators accepted drops
   a thin link below the threshold and stalls the sync.

The whole check sits inside the forward link walk. Each link must start where the last ended,
stay on the masterchain, and move forward by sequence number. The set is read from the source
key block's configuration proof, the destination header is read from its own proof and
required to match the link's claimed identity and key-block flag, the signed message is rebuilt
for the set's form, the verified distinct-signer weight is summed, and `carries` decides. Only
a key block carries a configuration, so a chain can be continued only from one; the walk
returns whether the block it proved is a key block for exactly that reason. A backward link is
refused by name in this release rather than half-checked.

## Alternatives considered

- **Implement the shuffle and the `gen_validator_list_hash_short` cross-check.** Rejected as
  redundant against a set derived correctly. Order affects neither membership nor weight, the
  only two things a signature check reads, and an incorrectly derived set already fails loudly
  at the threshold.
- **Use the parameter's declared total weight as the denominator.** Rejected. That figure
  counts every validator in every shard, while only the masterchain subset may sign a
  masterchain block. The signers and the denominator must come from the same set.
- **Compare with `>=`, or in floating point.** Rejected. Exactly two thirds must not carry,
  and at a 0.0046 percentage-point margin an `f64` comparison is unsound. The rule is strict
  greater-than in `u128` integers.
- **Deduplicate signatures before verifying.** Rejected. Verifying first is what stops a
  forged duplicate from displacing a real signature and dropping a link below the threshold;
  the compute amplification that ordering opens is closed by a per-link work budget instead.
- **Refuse a whole set over one bad signature.** Rejected. A set is a vote and carries junk
  from other rounds, so one corrupt or foreign entry is tolerated; refusing over it would let
  any peer stall a client.
- **Check the signing set's validity window against the block's generation time.** Rejected.
  The key block that announces a rotation is stamped one second past the outgoing set's
  `utime_until` and is signed by that outgoing set, so a window check refuses the first link of
  every rotation. The set to use is the one the source key block names, and the window is not a
  check.
- **Believe the destination on its Merkle header proof.** Rejected. The file hash is not in the
  cell tree, so no header proof covers it; only the signatures, which cover the root and file
  hashes together, bind it.
- **Adopt a stricter ed25519 rule than the network's.** Rejected. A rule that refuses more
  refuses signatures the validators accepted, which stalls a thin link rather than adding
  safety.

## Consequences

- A destination is believed only after signatures carrying more than two thirds of the source
  key block's set verify. The header proof says what a block claims; the signatures say it is
  the block the network committed.
- Verification is per link, and a sync is a run of links, each checked against the set the
  previous key block named. A validator-set rotation is handled by construction, since the set
  is re-read at every link.
- A set padded with duplicate signers, signed entirely by non-members, or lifted from another
  block cannot carry a link, and none of these can stall a client either.
- Two conditions this release does not handle are named failures rather than silent ones: a
  backward link and a signature set of an unknown form.

## Chain scope

TON-specific, and masterchain-only in this release. A link whose source or destination is not
the masterchain (workchain `-1`, shard `0x8000000000000000`) is refused. Composing several
chains lives above ton-net, in the consumer (NET-ADR-002, NET-ADR-003).

## Custody and security

No user keys, and no signing. This is read-path verification: the library checks signatures a
server presents and never produces one. The security property is negative and testable, a
block that the pinned set did not sign to more than two thirds of its weight is refused, and it
is grounded in code rather than asserted. The ed25519 primitive is the single vetted curve
implementation the workspace already carries (NET-ADR-004); its variable-time verification is
safe here because every input to it is public. This record does not change the custody
position set in NET-ADR-001.

## Verification

- Two whole `getBlockProof` answers captured from a mainnet liteserver on 2026-07-21, one per
  signed form, anchor the work. A three-link chain from masterchain 46894135 to 46920655,
  crossing one validator-set rotation and signed in the ordinary form, verifies end to end,
  and a one-link chain from 59238081 to 59379986 verifies in the Simplex form. A test confirms
  the three-link chain genuinely re-chooses its set across the rotation.
- The tamper cases decode a real answer, change one thing, and assert the specific error, not
  merely that one occurred. A flipped file hash yields no weight at all; an altered
  configuration proof stops the proof rooting; signatures moved to another link, a set signed
  by non-members, and a set of all-corrupt signatures each fail to carry; a duplicated set
  moves the carried weight by nothing; a Simplex set lifted onto another block is refused
  because its candidate no longer names the destination.
- The threshold is unit-tested at the boundary: weights divisible by three where exactly two
  thirds must not carry and one unit more must, and weights near `u64::MAX` where a 64-bit
  multiplication would wrap and the `u128` one does not.
- The ed25519 rule is pinned by a differential pass against an independent verifier over valid
  signatures and random corruptions, followed by the edge cases the two could disagree on,
  each built from curve arithmetic rather than transcribed: a small-order `A` and a small-order
  `R`, a non-canonical point encoding, a scalar at or above the group order, and an added
  torsion component that the cofactored equation would wrongly accept.
- Two negative controls show the signed form was established and not guessed. Checking a real
  set against `ton.blockIdApprove` (0x2dd44a49) instead of `ton.blockId`, or against a notarize
  vote (0xcdf605a8) instead of a finalize vote, makes every signature invalid, which is what a
  forged set looks like too, so they are told apart in a test. Every boxed type's constructor
  id is checked against the CRC32 of its TL scheme line, and an unknown constructor is refused
  rather than read.
