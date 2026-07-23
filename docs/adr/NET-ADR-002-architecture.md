---
id: NET-ADR-002
title: One audited core, a sans-I/O seam, thin bindings
status: accepted
date: 2026-07-23
supersedes: none
superseded-by: none
---

# NET-ADR-002: One audited core, a sans-I/O seam, thin bindings

## Context

ton-net speaks the TON client protocol and verifies every answer against validator
signatures rather than trusting a server, and it is distributed across language bindings
(NET-ADR-001). Two facts follow from that and shape everything below.

The first is that most of this library is adversarial. Decoding a TL message, reading a bag
of cells, checking a Merkle proof, and checking a validator signature set are all done over
bytes a server the client does not trust chose to send. That is the code a bug is most
dangerous in: a panic is a denial of service in the embedding process, and a verification
that accepts one thing it should not is the whole guarantee gone. The single internal audit
capability that NET-ADR-001 fixes audits this code.

The second is that the client runs in more than one place. A native process reaches a
liteserver over a TCP socket; a browser build reaches one over a WebSocket. The bytes on the
wire are the same ADNL frames either way.

Both facts point at the same question: where does the protocol and verification logic live,
and how many times is it written. Writing it once per binding language would put the
adversarial parsing and the proof checking in every language the library ships, multiply the
code that must be correct, and multiply the audit target; a parsing or proof defect in any
one of them reintroduces the risk the verification exists to remove. Binding I/O into that
logic would fork it again, once per socket kind. This record fixes the shape that avoids
both.

## Decision

1. **One core, in Rust.** The protocol and all of the verification are written once, in the
   Rust workspace crates, and no binding reimplements any of it. The TL codec is
   `ton-net-tl`; the encrypted ADNL handshake and stream framing are `ton-net-adnl`; the cell
   model, the representation hash, and Merkle-proof checking are `ton-net-cell`; block and
   account decode and the validator-signature-checked sync are `ton-net-block` and the
   `ton-net` facade (NET-ADR-005, NET-ADR-006); the local TVM lands in the same core when it
   is built (NET-ADR-007). Each crypto primitive is a single copy across that core
   (NET-ADR-004).

2. **A sans-I/O core.** The protocol logic produces bytes to send and consumes bytes
   received, and nothing more. The handshake and the framing are synchronous functions that
   touch no socket, no clock, and no randomness source: `client_handshake` builds the
   256-byte packet from a server key and the fresh randomness handed to it, and
   `SessionCiphers` seals and opens frames in place. The randomness a handshake needs, 192
   bytes of it, is carried in as a value so the function stays pure, and the one draw from the
   operating system sits in the async connection driver at the I/O edge. This is what lets the
   core be tested against fixed vectors with no network.

3. **A narrow transport seam.** I/O lives behind one trait, `Transport`, with two methods,
   `write_all` and `read_exact`, that move ordered bytes and do not frame them; framing is the
   core's concern. The connection driver is generic over the trait, so the call monomorphizes
   and adds no dynamic dispatch on the protocol path. `TcpTransport` implements the trait over
   TCP today. A browser WebSocket implements the same two methods in a later release, and the
   protocol code above the seam does not change.

4. **The facade is the single public surface.** `ton-net` composes the layer crates into one
   API and is the only crate a consumer or a binding depends on. The layer crates below it are
   internal. The facade is where the proved and unproved reads are carried in the type: a
   `ServerReported` value is a server's word, a `Verified` value was checked against a block
   hash the client established, and there is no way to turn the first into the second.

5. **Thin bindings.** A binding maps values across the FFI boundary and forwards to the
   facade. It carries no protocol logic and no verification. The Node binding is a single
   crate over `ton-net`: it turns reads into JavaScript-native shapes, holds the one
   connection behind an async mutex, and takes its error codes from the core's own list rather
   than a table of its own, so a new core error is a build failure in the core and never a
   silent unknown downstream. The proved and unproved distinction crosses as two shapes that
   cannot be confused. Node is the first binding; the binding sequence is NET-ADR-008.

The six core crates form a flat layered set, the TL codec and the cell model at the base and
the facade on top; the full structure and how a crate grows is NET-ADR-009.

## Alternatives considered

- **Reimplement the protocol per binding language.** Rejected. It puts the adversarial
  parsing and the proof checking in every language the library ships, multiplies the code
  that must be correct, and multiplies the audit target. A defect in one language's decoder or
  verifier reintroduces the risk the verification exists to remove, and the single internal
  audit capability audits one codebase, not one per language.
- **Bind I/O into the protocol code.** Rejected. Async socket calls inside the handshake and
  the framing fork the protocol once per I/O environment and make the core untestable without
  a socket and a clock. The sans-I/O seam keeps one protocol implementation across TCP and
  WebSocket and lets it run against fixed vectors.
- **A wide transport trait.** Rejected. A trait that also owns framing, timeouts, or the
  session pushes protocol back out of the core and into every transport and every binding. The
  seam is two byte-moving methods, and everything above them is written once.
- **Fat bindings that re-expose the layer crates or add their own decode.** Rejected. It
  duplicates surface and lets a binding's decode drift from the audited one. A binding depends
  only on the facade and reads what the facade already decoded and checked.
- **Ship the core as a Rust library only and let each consumer write its own binding.**
  Rejected. The adoption surface, including the bindings, is a maintained deliverable
  (NET-ADR-001), so the bindings are owned and kept thin by rule rather than left for a
  consumer to reinvent and get wrong.

## Consequences

- The audit has one target. It reads the Rust core; a binding review is a review of type
  mapping, not of parsing or proofs.
- A new binding is a mapping layer. It inherits every read and every check the core already
  has and cannot weaken them, because it holds none of them, so reaching a new language is
  bounded work (NET-ADR-008).
- A browser build reuses the whole core. Only a WebSocket `Transport` is new.
- The facade is the compatibility surface. The layer crates can change behind it while a
  consumer and a binding see only `ton-net`.
- The core stays free of sockets and clocks below the connection driver, which is what keeps
  the handshake and the framing testable against fixed vectors.
- The seam costs one trait call per byte-move and a binding costs one FFI copy per value. Both
  sit at the I/O edge, not on the parse and verify path, and the generic driver monomorphizes
  the transport call, so the shape carries no cost the performance bar counts (NET-ADR-001).

## Chain scope

TON-specific (NET-ADR-001). The seam and the core-plus-bindings shape are not TON-specific in
form, but the core they carry is; composing several chains lives above ton-net, in the
consumer.

## Custody and security

No user keys today (NET-ADR-001). The architecture's contribution to that position is that the
verification which makes a read trustworthy, the cell and Merkle checking and the
signature-checked sync, exists once and is audited once, and a binding cannot bypass or weaken
it because it carries none of it. The proved and unproved reads cross the FFI as two distinct
shapes, so a caller cannot mistake a server's word for a checked result.

The sans-I/O core takes its randomness as an input, and the single operating-system draw is at
the I/O edge. Because the core is shared, the checks in it are inherited by every transport and
every binding: the handshake aborts on the degenerate all-zero shared secret (RFC 7748 section
6.1), so no socket kind and no language can open a session on a secret an onlooker can also
derive.

The write path first touches key material through the signer seam, where a caller supplies a
callback and the library never sees a key, and that seam is fixed in NET-ADR-003. This record
fixes the code shape and does not change the custody position.

## Verification

- The seam is testable without a network. `client_handshake` and `SessionCiphers` are
  exercised against fixed vectors: the handshake packet layout and its decrypt-back, and frame
  seal and open, keystream advance, out-of-order desync, tamper rejection, and cross-session
  rejection, all with no socket.
- The single-core claim is observable in the layering. The six workspace crates hold the
  protocol and the verification, and the Node binding depends on `ton-net` alone.
- The no-logic-in-bindings rule is checkable. The binding reaches protocol and verification
  only through the facade, and its error codes resolve from the core's own enumeration, so a
  core error added without a matching binding arm fails the core's build rather than arriving
  as an unhandled case.
- The same core over a second transport is demonstrable. The generic driver runs over any
  `Transport`; TcpTransport shows it today, and a WebSocket transport reuses the driver
  unchanged.
