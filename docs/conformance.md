# Conformance

How a multi-language library stays one wire behavior, and how that behavior is
pinned to the TON reference node rather than to itself.

Governing decisions: [NET-ADR-001](adr/NET-ADR-001-architecture.md),
[NET-ADR-004](adr/NET-ADR-004-bindings-and-versioning.md).

---

## The two things conformance must guarantee

1. **Cross-language identity.** Node, browser, Swift, Kotlin, Python, and Dart
   must all behave identically on the wire. A single Rust core makes this
   structural, not aspirational: there is one serializer, one handshake, one proof
   verifier, and every binding calls it. There is no second implementation to
   drift. This is the libsignal and automerge lesson: a macro-or-wrapper over one
   core cannot diverge, so cross-language parity is correct by construction, and
   the suite only has to prove each binding *builds and links* against the core.
2. **Fidelity to TON.** The core must match the reference node's wire behavior
   exactly. This is where the vectors do real work: a byte-exact corpus generated
   against `ton-blockchain/ton`, so a change in the core that diverges from TON
   fails, not just a change that diverges from a previous ton-net.

Conformance is therefore mostly about (2). (1) is handled by architecture; (2) is
handled by vectors.

---

## The vector corpus

Canonical inputs paired with their exact expected bytes or verdicts, generated
against the reference node and checked in every language's CI. Five families:

**TL vectors.** For each schema type ton-net serializes, an input value and its
exact serialized bytes, both directions. Includes the CRC32-IEEE constructor-tag
derivation (empirically the reference computes `pub.ed25519` = `0x4813b4c6`,
`pub.aes` = `0x2dbcadd4`, `adnl.message.query` = `0xb48bf97a`; the suite pins these
and regenerates the rest from the schema). A binding that produces different bytes
fails.

**ADNL handshake vectors.** A fixed ephemeral keypair and peer key, and the exact
256-byte TCP handshake, the s1/s2/v1/v2 session-key split, and a sample encrypted
stream frame (length, nonce, payload, checksum) that must result. Pins the exact
byte layout that the wire-format map documents.

**DHT key-id vectors.** The `SHA256(boxed dht.key{id, name, idx})` derivation for
known inputs, plus a `findValue` request and its expected serialization. One wrong
byte here resolves nothing, so it is pinned tightly.

**Proof vectors.** Real liteserver responses (account state, config, a block
proof) captured from mainnet, paired with the trusted block hash they verify
against and the expected verified value. A tampered variant (one flipped byte in
the Merkle proof BoC) paired with the expected `BadProof` verdict. This is the
most important family: it is the trust guarantee under test. It exercises exotic
cells, level masks, and the five `check_*_proof` routines against ground truth.

**TVM vectors.** Get-method calls for a corpus of real accounts (wallet `seqno`
and `get_public_key`, jetton `get_wallet_data`, DNS resolution, common contracts)
over proven code and data, paired with the exact stack the reference node's TVM
produces. This measures execution fidelity, the one property a local TVM must have
(NET-ADR-005).

---

## How the vectors are generated and run

- **Generated against the oracle.** A `tools/` step drives the reference node (or
  captures real mainnet liteserver responses) and emits the vector files. The
  oracle is `ton-blockchain/ton`, not a previous ton-net; this is what makes the
  suite catch divergence from TON rather than just regressions against itself.
- **Run per binding in CI.** Each language's CI loads the same vector files and
  asserts its binding reproduces them: same TL bytes, same handshake, same key-id,
  same proof verdict, same TVM stack. Because there is one core, this mostly
  confirms the binding is wired correctly and the artifact built; the real
  behavioral assertions live at the Rust level.
- **Fuzzing on the untrusted boundary.** A libFuzzer target over the TL
  deserializer (the automerge pattern: fuzz the load/parse path) runs in CI and
  must not panic, hang, or over-allocate on arbitrary input. The proof parser gets
  the same treatment, since it too consumes attacker-controlled bytes.
- **Negative corpus.** Tampered proofs, forged DHT records, malformed packets, and
  a non-terminating get-method, each paired with the expected rejection, so the
  suite proves the library says no when it should, not only yes when it should.

---

## Bring-up: differential testing, then the vectors stand

During development, before the vector corpus is complete, every resolved address,
every proof, and every block-sync walk is cross-checked live against the reference
node and a known-good client (pytoniq, tonutils-go) until agreement is consistent.
Then the crutch is dropped and the pinned vectors carry the guarantee. This is the
libsignal cross-version approach adapted: agreement is established against an
external oracle first, then frozen into vectors that stand without it.

---

## What conformance does not do

- It does not re-verify cross-language identity by re-running logic in each
  language: there is no per-language logic to re-run, only bindings over one core.
  Asserting each binding builds and reproduces the vectors is sufficient and
  honest.
- It does not treat a previous ton-net release as the oracle. The oracle is TON.
  A ton-net change that both the code and an old ton-net agree on, but the
  reference node rejects, must fail, and only a TON-anchored vector catches that.
