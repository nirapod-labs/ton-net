# Block-sync feasibility spike

A standalone program that walks TON mainnet's whole block-proof chain, from the block
the network config pins to the current head, checking every validator signature on the
way. It answers the questions [docs/plan/v0.3.0.md](../../docs/plan/v0.3.0.md) could
not answer by reading, before the v0.3.0 build starts.

It reuses the layers v0.1.0 and v0.2.0 already proved, ADNL for the network and the
cell engine for the proofs, and hand-rolls exactly what v0.3.0 adds: the block-proof
wire types, the block header and validator-set decode, and the signature check.

## Run

```
cargo run --release --bin sync-spike          # the whole walk
cargo run --release --bin sync-spike -- 4     # stop after four rounds
cargo run --release --bin analyse             # work out a signed message from a capture
```

It needs outbound TCP to the mainnet liteservers listed in `main.rs`. A full walk
downloads about 53 MB.

## What it establishes

Run on 2026-07-21, from `init_block` seqno 46894135 to head seqno 81057314, a span of
460 days.

- **A public liteserver does serve a proof chain from a block that old.** This was the
  design's largest unknown: ordinary blocks are pruned, and if key blocks were pruned
  with them the config's pinned block would be unreachable and the whole anchor story
  would need rewriting. The first reply came back in 1.6 seconds.
- **Sixteen links per reply, and no backward links in 1242.** An honest chain from a
  key block is forward-only, which is what lets v0.3.0 keep its anchor on key blocks
  and leave backward links unbuilt.
- **The masterchain validator set is the first `min(main, total)` entries of parameter
  34.** Mainnet runs about 100 main out of about 380 total, and across 107475
  signatures not one signer fell outside that head-of-list subset. Had the subset been
  wrong, roughly three quarters of signers would have been unrecognised.
- **Two signed forms, and the newer one is now the only one in use.** Up to seqno
  59379986 a signature covers `ton.blockId`. From that block on, sets arrive in the
  Simplex form and a signature covers a vote instead. A client that speaks only the
  older form stops three quarters of the way to the head.
- **Ed25519 verification needs no new dependency.** It is built here on
  `curve25519-dalek` and `sha2`, both already in the tree, and verified 107475 real
  mainnet signatures.

Full result:

```
rounds           78
links            1242
backward links   0
signatures       107475 checked
validator sets   608 distinct, so 607 rotations crossed
signed forms     ton.blockId from seqno 46897112, simplex.finalizeVote from seqno 59379986
thinnest margin  66.6712% at seqno 62275169, 0.0046 points above two thirds
received         52.6 MB
elapsed          153.6s (148.2s of it waiting on the network)
per link         43.4 kB
```

## The margin, and why it decides the signature rule

The thinnest link on the whole chain carries 66.6712% of its validator set's weight
against a two-thirds threshold: 0.0046 percentage points of headroom, which is about a
two-hundredth of a single validator's weight.

Two rules follow, and neither is a preference.

**The threshold is integer arithmetic and strictly greater.** `weight * 3 >
total_weight * 2`, with no rounding and no floating point anywhere near it. At this
margin a comparison done in `f64` is a coin toss.

**The acceptance rule for one signature must match the network's, not exceed it.** The
tempting position is that stricter is safer, since a stricter rule can only refuse. At
a margin of 0.0046 points, refusing one signature the validators accepted stalls the
sync. So the target is libsodium's `crypto_sign_verify_detached`, which is what the
validators sign and verify with: canonical `A`, `R` and `S`, neither `A` nor `R` of
small order, and the uncofactored equation. This client aims to accept exactly that
set, no more and no less.

## How the Simplex message was established

The Simplex signature sets did not verify under any obvious message, so the format was
worked out rather than guessed. `analyse.rs` loads a captured set and tries a
structured space of candidate messages against 66 real signatures. Ed25519 is an exact
oracle here: a wrong message verifies nothing at all and the right one verifies
everything, so there is no ambiguity in the answer.

The first 1059 candidates all scored zero, which narrowed it to a wrapper rather than a
field. The reference implementation supplied the missing piece: a vote is never signed
on its own, but placed in a `consensus.dataToSign` beside the consensus session id, so
a signature from one session cannot be replayed into another.

```
message = consensus.dataToSign {
    session_id,
    data = consensus.simplex.finalizeVote {
        id = consensus.candidateId {
            slot,
            hash = sha256(candidate)
        }
    }
}
```

All 66 signatures verified. `slot` and `session_id` come from the signature set; the
`candidate` bytes it also carries are a serialized `consensus.candidateHashData`,
shipped whole so a client can hash it without decoding it. Reading one anyway confirms
it names the same block the link does, and carries the parent candidate id, which is
what makes the hash convention self-evident: the parent's id has the shape this
block's id must have.

The vote is a `finalizeVote`, not a `notarizeVote`. That is the right thing for a block
proof to rest on: finalization is what commits a block.

## Two layout traps it caught

**A block's extra has three references before its data.** Reading the masterchain extra
by taking the next reference after the maybe-bit lands on `in_msg_descr` instead. The
reference cursor has to be walked past all three first, which the first run failed on
with a pruned-cell error that looked like a server problem and was not.

**A rotation key block sits one second outside its own signing set's window.** The set
named by key block 46894135 runs to `utime_until` 1744850696, and the block it signs is
stamped 1744850697. A validity check that required the destination's `gen_utime` to
fall inside the source set's window would refuse the first link of every rotation, and
there are 607 of them. The set to use is the one the source key block names, and the
window is not a check.

## What it deliberately does not do

- No `gen_validator_list_hash_short` check, and so no seeded shuffle. The shuffle
  permutes the head-of-list subset without changing membership or weight, so it cannot
  change which signatures are accepted. The 107475-signature run is the evidence that
  the subset is right.
- No backward links. None appeared, and an anchor kept on key blocks never needs one.
- No trimmed corpus. The captures under `captured/` are whole replies of about 700 kB;
  the hermetic fixtures the library tests need are a handful of links, one of each
  signed form, and trimming them is v0.3.0's own work.
