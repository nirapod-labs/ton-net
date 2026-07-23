# Conformance

## What conformance means here

ton-net verifies every answer against validator signatures rather than trusting
the server that gave it (NET-ADR-001). Its correctness claim is not that it agrees
with some other program. It is that the identities it computes are the identities
the TON network already committed to: the same cell hashes, the same block ids, the
same dictionary roots, the same signed bytes. Conformance is established by holding
the library to those facts.

The oracle for every check in this document is a value the network produced,
captured once and pinned. A cell tree hashes to the id a liteserver served it under.
A dictionary rebuilt from its own entries returns to the root hash the validators
wrote. A proof verifies against a block hash a second, independent source published.
No check compares ton-net against another implementation, and no check lets the
server that supplied the bytes also supply the answer those bytes are graded on
(NET-ADR-006).

## Why the oracle comes from outside

A round trip proves nothing about conformance. Parsing bytes and writing them back
re-reads whatever was written, so an encoder that made one consistent wrong choice
passes its own round trip every time. The dictionary engine is the clearest case: an
edge label has one canonical encoding and several that read back to the same label,
and a client that picked a non-canonical one would build a tree that reads correctly,
hashes differently, and fails every proof it is put to, with nothing reporting a
fault (`crates/ton-net-block/tests/dictionary.rs`). The only thing that catches that
is a hash the library did not compute.

Two independent sources supply those hashes.

- **The network itself.** A bag of cells carries the hashes and ids its sender
  computed. A whole block names its own root, a Merkle proof names the block it
  covers, and an augmented dictionary carries the summary the validators totalled.
  Recomputing SHA-256 over the sender's bytes and landing on the sender's value is a
  check the sender cannot pass by lying, only by being correct.
- **A second party**, for the values a single server could otherwise invent. A block
  hash used as a trust anchor, the shard block hash the engine derives, the balance
  an account decodes to, and the validator set a key block names were each confirmed
  against a public API independent of the liteserver that sent the proof, before
  being pinned (`crates/ton-net-block/tests/verify.rs`, `decode.rs`, `validators.rs`).
  The validator-set figures were read from tonapi.io on 2026-07-21. A test that took
  its anchor from the same server that sent the proof would prove nothing, because a
  server that made up a block can make up a proof that roots at it.

Matching mainnet is the bar rather than matching a reference because the network is
the thing a client has to be correct against (NET-ADR-001). Being stricter than the
network is not a free safety margin: on the real chain the signature margins are thin
enough that refusing one signature the validators accepted stalls a sync rather than
hardening it (NET-ADR-006).

## The captured fixtures

The fixtures are bytes a mainnet liteserver actually returned, captured by the
`spikes/proof-feasibility` and `spikes/adnl-feasibility` probes. Every byte in a
fixture is the server's; comment lines marked with `#` record provenance and are not
part of the data. The anchors and reported values a fixture is graded against were
confirmed against an independent source before being pinned, so a decode or a
derivation that drifts is caught rather than left agreeing with itself.

The whole conformance suite runs offline. It replays the captured bytes and never
reaches the network, so it is deterministic and reproduces the same verdict on every
run. The live-network tests are separate and are covered under
[Hermetic checks and live checks](#hermetic-checks-and-live-checks).

## The four identities a fixture must reproduce

Conformance rests on four kinds of identity, each an equality between what the library
computes and what the network already computed.

### A real account proof verifies against the block it was read at

A captured `getAccountState` answer is a masterchain block hash, a shard proof, an
account-state proof, and the account state. `verify_account` recomputes hashes up the
proof to the pinned block hash and binds the separately delivered state to it. The
masterchain zero address decodes to a balance of 222,859,282,039,087 nanotons and the
basechain fixture to 1,067,259,229,327, each the figure an independent public API
reported (`crates/ton-net-block/tests/verify.rs`). The shard block that carries a
basechain account is derived from the masterchain state rather than believed from the
server's word, and the derived hash equals one a second source published
(`the_shard_block_is_derived_from_the_masterchain_rather_than_believed`). An address
nothing was ever stored under is proved absent, not merely reported absent.

The same engine that checks a liteserver's proof accepts a proof this workspace builds
over the same tree, against the same externally confirmed hash, and refuses one built
for any other root (`crates/ton-net-block/tests/proof.rs`).

Accepting the true answer is half of the property. The other half is refusing every
near miss a lying server would send, and each tamper case asserts the specific error
it must return rather than that some error occurred:

- an anchor that is not the block the proof covers, and a proof crossed in from another
  block, are `ProofNotAnchored`;
- another account's valid state, an empty state paired with a covering proof, a
  placeholder cell that carries the right hash and no contents, and a subtree whose
  contents were pruned away under an unchanged parent hash are `NotBound`;
- a pruned accounts dictionary read as an empty one, and an account the proof prunes
  away, are `NotCovered` rather than a forged proof of absence.

Two single-byte sweeps close the gap a sampled set of cases leaves. Every byte of the
account state, flipped in turn, is refused, because every byte is hashed into the hash
the proof binds. Every byte of a proof is flipped in turn, and the requirement is not
that all are refused but that none produces a *different* account: a proof carries
pruned branches whose upper hash slots a single-path read never touches, and editing an
unread slot cannot and should not change the answer. The suite requires the great
majority to be refused and the accepted remainder to be byte-identical to the untampered
result (`no_edit_to_a_proof_changes_the_answer`, `no_edit_to_the_account_state_changes_the_answer`).

### A rebuilt mainnet dictionary reproduces its own root hash

A hash is the oracle for dictionary structure, because it was computed by the network
over bytes this crate did not write, so reproducing it means every label, every fork,
and every ordering decision came out the way TON makes them
(`crates/ton-net-block/tests/dictionary.rs`).

Six dictionaries are pulled from captured mainnet proofs at key widths of 16, 32, and
256 bits: the validator list, the network configuration, the masterchain shard hashes,
and three shard-accounts dictionaries. Each is rebuilt from its own entries and held to
the root hash the network computed, in both key orders, because a radix tree has one
shape per key set and a wrong split or merge is what would make the arrival order
matter. The bulk `from_items` path is held to the same hash. A key added and then
removed must leave the tree exactly as it stood, hash included. A sub-dictionary carved
one byte narrower must equal a fresh build over the stripped keys. A second label reader,
written from `block.tlb` rather than from the library, confirms that every one of the
886 labels the corpus holds is written the way mainnet wrote it, and the corpus is shown
to exercise all three label encodings so the canonical choice is tested where the forms
actually compete.

Augmented dictionaries carry a summary of each subtree in the fork above it, and the
summary is part of what the hash covers. The `account_blocks` of basechain block
86062610 holds eleven entries over ten forks, whose grams sum to 3,942,413, exactly the
total the validators wrote in the block's own summary. The dictionary rebuilds to the
validators' root hash `5cb7df25…` in both orders, through the single-key path and the
bulk path, and after splitting into halves and combining them back
(`crates/ton-net-cell/tests/cell/augmented.rs`). Every fork is checked to summarise the
two subtrees below it, which is the rule read off mainnet rather than assumed. A summary
cannot be invented for a subtree a proof pruned away, and each dictionary shape refuses
the other on the way in, so a plain writer cannot silently drop a summary and an
augmented one cannot read a plain fork.

### A whole block hashes to the id it was served under

A whole block is the form that carries a complete dictionary and a Merkle update of the
state whose two subtrees are pruned, so it is where exotic cells and stored hashes appear
in the same bag. The masterchain and basechain whole-block fixtures each parse to one
root, and that root's representation hash equals the id the liteserver served the block
under, `e55bf967…` and `80cbafe6…` (`crates/ton-net-cell/tests/cell/whole_block.rs`).

A bag may write a cell's hashes and depths ahead of its data. The two blocks together
hold 1428 cells, of which 44 carry their own hashes; those are recomputed and checked
rather than trusted, and a cell whose stored hash or depth disagrees with its own
contents is refused as `Malformed`. Rewriting a block drops the stored copies, because a
cell's identity comes from its contents, so the bytes come out shorter and the tree comes
out the same.

The memory-bounded read paths are held to the same served id. `BocView::verify` keeps a
summary per cell rather than the cell, and over a whole block it reports the root a full
parse computes and the id the block was served under. `BocView::cell(0)` builds only the
root's subtree by random access and hashes to that same id. This is the consumer-priority
guard from NET-ADR-001 made testable: a scale path must agree with the in-memory path
rather than diverge from it.

### The streaming serializer matches the whole one byte for byte

The chunked serializer must be the one-buffer serializer byte for byte, on a bag the node
produced rather than one this crate wrote. `serialize_boc_chunks` flattened equals
`serialize_boc` over the captured account proof, and the streamed bytes parse back to the
same cell identities (`the_streaming_serializer_matches_the_whole_one_on_a_real_bag` in
`crates/ton-net-cell/tests/cell/mainnet_boc.rs`). This is the byte-for-byte agreement
between a scale path and the in-memory path that NET-ADR-001 requires of every scale
operation.

## Cell hashing and Merkle proofs

The level rule for exotic cells is the piece a proof engine gets subtly wrong, so cell
hashing is measured against the well-known empty-cell hash
`96a296d2…` and against a captured proof whose Merkle cells carry the hashes the node
computed for the trees they cover (`crates/ton-net-cell/tests/cell/hashing.rs`).
Virtualizing each proof in the captured bag reads back the tree it stands for, and that
tree hashes to the root the proof claims, one of which is a block hash recorded when the
bag was captured. Pruning runs the other way: a whole block is recorded down to one path
and rebuilt with the rest stood in for, and the pruned block still hashes to the id it was
served under. A proof built here over the tree a server's proof stands for reproduces that
server's proof cell byte for byte (`crates/ton-net-cell/tests/cell/merkle.rs`).

## The signature rule

Signature verification is the one place the oracle is another implementation, and for a
principled reason: the fact about mainnet for a single signature is exactly which
signatures the validators' own software accepts, which is libsodium's
`crypto_sign_verify_detached`. ton-net pins that rule rather than inheriting a stricter
one, because being stricter than the network stalls a thin link instead of hardening it
(NET-ADR-006).

The rule is established two ways (`crates/ton-net-block/tests/signature.rs`). A
differential pass compares this crate against `ed25519-dalek`'s `verify_strict` over valid
signatures and over random single-byte corruptions of them, and requires the two to agree
on every input. `ed25519-dalek` is a development dependency and does not ship; it also
produces the valid signatures, because signatures generated by the code under test would
prove only that it agrees with itself. The edge cases the two verifiers could disagree on
are then stated one at a time and built out of curve arithmetic rather than transcribed as
hex, so a wrong constant cannot make a case pass by not being the case it claims: a
small-order public key, a small-order `R`, a non-canonical point encoding, a scalar at or
above the group order, and an added torsion component that a cofactored equation would
wrongly accept. A guard on the guards checks that the basepoint is not small order, so a
small-order test broken toward accepting everything would not pass silently.

## Validator sets and the proof chain

A key block names a validator set in configuration parameter 34, and the set a captured
key block names matches what an independent explorer reported at the same sequence number:
the signing window, the counts of `total` and `main`, the summed weight of the signing
subset, and the first validator's key and weight, all read from tonapi.io on 2026-07-21
(`crates/ton-net-block/tests/validators.rs`). Two rounds twelve million blocks apart are
shown to be different sets, so the match cannot be passing on a set read from the wrong
block.

A whole `getBlockProof` answer of three forward links, from the block the mainnet config
pins forward across one validator-set rotation, verifies end to end, and a test confirms
the chain genuinely re-chooses its set across the rotation rather than reading one set and
reusing it (`crates/ton-net-block/tests/chain.rs`). A one-link answer in the newer Simplex
signed form verifies too. The tamper battery decodes a real answer, changes one thing, and
asserts the exact error: a removed, transposed, reversed, or backward link; an inverted
key-block flag; a link out of the masterchain; a changed file hash, which no Merkle proof
covers and only the signatures notice, carrying no weight at all; signatures moved to
another link; a set signed entirely by non-members or entirely corrupt; a duplicated set
that moves the carried weight by nothing; and a Simplex set lifted onto another block,
refused because its candidate no longer names the destination. Four hundred rounds of
hostile bytes fed to the proof fields as attacker-controlled input resolve to a refusal
and never a panic.

## The wire and the handshake

Every boxed TL type's constructor id is checked to equal the CRC32 of its scheme line, and
every type round-trips through serialize and deserialize
(`crates/ton-net-tl/tests/wire.rs`). The block-proof types are anchored harder: two whole
`getBlockProof` answers a mainnet liteserver gave, one per signed form, are decoded and
re-encoded and must come back byte for byte, which pins the layout to TON rather than to
this crate's encoder. Two negative controls show the signed form was established and not
guessed: checked against a different constructor id, every signature turns invalid, which is
what a forged set looks like too, so the cases are told apart by test. The ADNL handshake and
framing are pinned by fixed public-API byte vectors that anchor the exact layout a mainnet
liteserver accepted in the feasibility spike (`crates/ton-net-adnl/tests/vectors.rs`).

## The verification epoch

`ton_net::VERIFY_EPOCH` records which build's accept-and-reject boundary is in force, and a
constant alone cannot keep that promise, because nothing stops an edit from changing what
verifies while the number stays put (NET-ADR-008). So the boundary is pinned as a
transcript: one captured masterchain read and ten edits chosen to sit on the decision
boundary are each run through the public facade and their verdicts recorded, and the whole
transcript is compared against the text the test carries
(`crates/ton-net/tests/epoch.rs`). A change to what the engine accepts fails the test, which
is the moment to decide whether the epoch moves and to record in the changelog what is now
accepted or refused that was not before. Verdicts use error codes rather than messages, so
rewording a message is free and reclassifying a verdict is not.

## Hermetic checks and live checks

The conformance suite is hermetic. It runs under `cargo test`, replays only the captured
fixtures, and never opens a socket, so it is the deterministic part of the evidence and the
part that gates a change.

A separate set of tests reaches a live mainnet liteserver and is marked `#[ignore]` so the
hermetic suite never triggers it; a dedicated network CI job runs it with `--ignored`. These
do not re-establish conformance. They confirm that the pinned byte layouts still open an ADNL
session and read a plausible head from a real node (`crates/ton-net-adnl/tests/mainnet.rs`,
`crates/ton-net-lite/tests/mainnet.rs`, `crates/ton-net/tests/mainnet.rs`), and that the
bundled mainnet snapshot has not decayed past a floor of reachable liteservers or let its
pinned block recede out of reach (`crates/ton-net/tests/snapshot.rs`). The captured fixtures
are what a change is measured against; the live tests are what warns that a capture has aged.

## Cross-implementation conformance vectors

What exists today is an internal oracle: captured mainnet fixtures, checked offline against
hashes the network computed and values a second source confirmed. There is no published set
of executable vectors that another implementation can run against itself, and this document
does not claim one. A healthy adoption surface, including conformance vectors an outside
project could adopt without any outreach, is a stated goal of the project rather than a
present deliverable (NET-ADR-001), and the versioned form such vectors would take is part of
the versioning and bindings track (NET-ADR-008). Until then, the fixtures and tests below are
the conformance evidence.

## Where the evidence lives

| Area | Tests | Fixtures |
|---|---|---|
| Bag of cells, real bytes | `crates/ton-net-cell/tests/cell/mainnet_boc.rs` | `fixtures/account-proof.hex` |
| Whole block hashes to its id | `crates/ton-net-cell/tests/cell/whole_block.rs` | `fixtures/block-masterchain.hex`, `fixtures/block-basechain.hex` |
| Augmented dictionaries | `crates/ton-net-cell/tests/cell/augmented.rs` | `fixtures/block-basechain.hex` |
| Cell hashing, Merkle proofs | `crates/ton-net-cell/tests/cell/hashing.rs`, `merkle.rs` | `fixtures/account-proof.hex`, `fixtures/block-basechain.hex` |
| Hostile and corrupted input | `crates/ton-net-cell/tests/cell/hostile.rs` | `fixtures/account-proof.hex` |
| Account read verification | `crates/ton-net-block/tests/verify.rs`, `proof.rs` | `fixtures/read-masterchain.txt`, `read-basechain.txt`, `read-absent.txt` |
| Dictionary engine | `crates/ton-net-block/tests/dictionary.rs` | `fixtures/chain.hex`, `read-*.txt` |
| Account decode | `crates/ton-net-block/tests/decode.rs` | `fixtures/active-account.hex`, `uninit-account.hex`, `storage-extra-account.hex`, `account-proof.hex` |
| Proof chain and signatures | `crates/ton-net-block/tests/chain.rs`, `validators.rs`, `signature.rs` | `fixtures/chain.hex`, `one-link-simplex.hex` |
| TL wire format | `crates/ton-net-tl/tests/wire.rs` | `fixtures/one-link-ordinary.hex`, `one-link-simplex.hex` |
| ADNL handshake vectors | `crates/ton-net-adnl/tests/vectors.rs` | inline |
| Verification epoch | `crates/ton-net/tests/epoch.rs` | `fixtures/read-masterchain.txt`, `read-basechain.txt` |
| Live-network checks (`#[ignore]`) | `crates/ton-net-adnl/tests/mainnet.rs`, `crates/ton-net-lite/tests/mainnet.rs`, `crates/ton-net/tests/mainnet.rs`, `crates/ton-net/tests/snapshot.rs` | live |

Fixture paths are relative to the `tests/` directory of the crate named in the same row.
