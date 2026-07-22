<!--
SPDX-License-Identifier: Apache-2.0
SPDX-FileCopyrightText: 2026 Nirapod Labs
-->

# Threat model

What an attacker controls at each boundary this library crosses, what the code
refuses, and what it does not. The README states the conclusion in two
paragraphs; this is the working out, so that a claim can be checked against the
function that makes it true rather than believed.

The scope is what ton-net does today: reading TON through a liteserver. Sending
is not in it, because the library does not sign or broadcast anything, so there
is no key to steal here and no transaction to alter.

## The attacker

**A liteserver is assumed hostile.** Not distrusted as a precaution: hostile as
the design case. Anyone can run one, the bundled configuration lists eighteen
operated by people this project has never met, and a client picks whichever
answers. Every guarantee below has to survive a server that answers with
whatever it likes.

That is the whole reason the library exists. A client that believes what a
liteserver says has outsourced the question "what is my balance" to a stranger.

**A network attacker** on the path is a weaker case than the above, because a
hostile server can do everything a network attacker can and more. It is worth
naming separately only where the transport is what stops it.

**A local attacker** with the process memory or the ability to move the system
clock is out of scope, except that the clock has a section below, because moving
it is the one local capability that changes an answer rather than reading one.

## Boundary 1: the transport

An ADNL session runs over TCP to an address and public key from the
configuration.

**What an attacker controls.** Every byte in both directions, if they are on the
path. The server's own bytes, always.

**Refused.**

- A server that cannot prove it holds the private key for the configured public
  key. The handshake derives the session keys from a shared secret with that
  key; an impostor derives different keys and every frame after it fails to
  decrypt.
- A degenerate key exchange. A low-order server key decompresses cleanly but
  drives the shared secret to zero, which would hand both sides a session key an
  observer can compute. Refused rather than used.
- A frame whose checksum does not match its contents, and a length field past
  what the protocol allows.
- Reuse of a connection whose read was cancelled mid-frame. The stream cipher
  has already advanced, so every later frame would decrypt to noise; the
  connection is marked `Desynchronized` instead of being returned to the pool.
- A call with no answer, and a call whose answer arrives after `CALL_TIMEOUT`.

**Not refused.** The server chosen from the list is the server talked to. There
is no quorum across servers, so a single hostile server is the ordinary case,
not a detected one. It cannot lie about chain contents, which is boundary 3, but
it can stall, disconnect, or answer nothing at all. Availability is not a
property this library provides; correctness under a hostile server is.

Traffic analysis is out of scope. The session is encrypted, and an observer
still learns that a TON liteserver is being talked to, and roughly how much.

## Boundary 2: the bytes

Everything a server sends is parsed before it is checked: TL messages, ADNL
frames, bags of cells, TL-B structures inside them.

**What an attacker controls.** The entire input, including length fields, cell
counts, reference indices, and depths. A parser here is the first thing that
touches attacker-chosen bytes, and it runs inside whatever process embedded the
library.

**Refused.** Structurally, by bounding every count before anything is allocated
for it: `TooManyCells` above 2^17, `TooDeep` past 1024 references, `TooWide`,
`NotEnoughBits`, `NotEnoughRefs`, `BadReference` for an index that points
outside the bag or backwards, `Truncated`, `Checksum`, `NotABagOfCells`.

**The property that matters more than any single check** is that a decoder
returns an error rather than unwinding. A panic in a parser is a denial of
service in the host process, so `unwrap`, `expect`, `panic`, `unreachable`,
`todo` and slice indexing are denied in every library crate, and the exceptions
are named in the source with the argument for why the case cannot arise.

Two properties in `ton-net-cell` assert the outcome rather than the coding rule:
arbitrary bytes and truncated encodings are refused and never fatal. Arithmetic
is deliberately outside that lint set, which is why the properties exist: an
overflow would still abort a debug build, and one did, in `Slice::load_bytes`,
where a byte-to-bit multiplication wrapped and the length check passed on the
wrapped value.

**Not refused.** Resource use within the bounds. A server can send a bag that is
large but legal and make the client do the work of parsing it.

## Boundary 3: the proof chain

This is the boundary the library is for.

**What an attacker controls.** The contents of every answer: blocks, proofs,
signature sets, account states, and the claim that a sync is complete.

**Refused.**

- A proof that is not a Merkle proof (`NotAMerkleProof`), or whose root does not
  hash to what it claims (`ProofInconsistent`).
- A proof not anchored to the block it is supposed to answer for
  (`ProofNotAnchored`), and a subtree the proof does not actually cover
  (`NotCovered`).
- A link that does not connect to the previous one (`ChainBroken`), and one that
  runs backwards (`BackwardLink`).
- A signature set carrying less than two thirds of the weight of the validator
  set that had to sign (`NotEnoughWeight`). The validator set is derived from
  each key block's own configuration proof, not taken from the server.
- A signature set in a form this release does not recognise
  (`UnknownSignedForm`), rather than assumed to be one it does.
- A withheld account dictionary presented as a proved absence. A pruned
  dictionary and an empty one both open with a clear bit, so the two are
  distinguished explicitly and a withheld answer is refused rather than read as
  "no such account".
- A substituted account body under a level-1 pruned branch, which answers for
  the hash it replaced.
- A pruned branch carrying references, which would otherwise hash the same
  whatever hangs beneath it.

**The guarantee.** A value that reaches a caller as `Verified<T>` was proved
against a block reached by a signature-checked walk. That type cannot be
constructed outside the crate, so it is not a label a caller can apply to
something unproven.

**Not refused.** A server can refuse to answer, answer slowly, or serve a
genuine older chain. The first two are availability. The third is the clock's
job.

## Boundary 4: what is still trusted

Two things, and they are the whole list.

**The pinned block.** A walk starts somewhere, and that somewhere is the key
block in the network configuration. Fetching it would move the root of trust to
whoever served it, and every later proof would then verify cleanly against
whatever chain that party invented, which is why the configuration is bundled
and the anchor is never fetched. A caller who does not want to trust that file
passes their own block: `Client::connect_from` takes one, and
`BlockIdExt::new` constructs one from an identity obtained out of band.

The liteserver list in the same file needs no trust at all, since every answer
from it is proof-checked. The two halves of that file have opposite trust
requirements, which is why `Config::mainnet` says so.

**The local clock.** A proof establishes that a block is real and was committed.
It says nothing about when it was handed over, so a server replaying a genuine
chain from last year passes every check above. The clock is the only thing that
catches that.

The library treats a clock more than `MAX_CLOCK_SKEW` (300 seconds) behind the
proven head as the thing that is wrong, and reports `ClockBehind` rather than
passing: to a clock a year behind, every block from the last year reads as brand
new and the freshness bound stops applying at all. Within tolerance, a head
older than the caller's limit is `Stale`.

So a client whose clock is wrong has a weaker freshness guarantee than one whose
clock is right, and it is told, instead of being told nothing.

## What this model does not cover

- **Sending.** No signing, no broadcast, no key handling. When that arrives it
  is a different model.
- **TVM execution.** Get-method results are the server's word today
  (`ServerReported`); NET-ADR-010 covers what a local TVM would change.
- **DHT.** Peer discovery is v0.8.0. Until then the server list is the
  configuration's.
- **Supply chain.** Covered by the dependency policy in `deny.toml`, the pinned
  actions, and the notices, not here.
- **Availability.** Named in three places above because it keeps recurring: this
  library is about not being lied to, not about always getting an answer.
