# ton-net

A TON network client written once in Rust, verified against validator signatures, and bound
natively into other languages.

ton-net is the reference Rust full TON client. It speaks TON's own client protocol directly,
TL over ADNL, and verifies every answer against the validator signatures that committed it
rather than trusting the server that returned it. The protocol and all of its verification are
one audited Rust core, and each supported language reaches TON through a thin native binding
over that core, so the adversarial parsing and the proof checking are written and reviewed
once rather than reimplemented per language ([NET-ADR-002](docs/adr/NET-ADR-002-architecture.md)).
It is an open-source client in its own right; the Nirapod wallet is one consumer of it, not
its reason to exist ([NET-ADR-001](docs/adr/NET-ADR-001-purpose-and-priorities.md)).

The scope is everything a program talking to TON needs, and it stops there. ton-net consumes
the network and verifies it. It never becomes a node: it does not serve values to peers, run
consensus, or produce blocks ([NET-ADR-003](docs/adr/NET-ADR-003-scope-and-write-path.md)).

## The one guarantee

A read is trust-minimized end to end. Nothing is believed but one pinned block and the local
clock; every other fact is earned by cryptography.

- **Block sync establishes a trusted block.** A client's root of trust is a single masterchain
  key block named in the network config. A sync walks forward from it to the network's current
  head one link at a time, and believes a destination block only once validators holding more
  than two thirds of the source key block's set have signed for it
  ([NET-ADR-005](docs/adr/NET-ADR-005-trust-anchor.md),
  [NET-ADR-006](docs/adr/NET-ADR-006-signature-verification.md)).
- **The proof engine verifies responses against that block.** A liteserver answer for an
  account carries Merkle proofs. ton-net checks them against the block it proved, so nothing
  the server states about the read is taken on its word
  ([NET-ADR-005](docs/adr/NET-ADR-005-trust-anchor.md)).
- **The API keeps a proven value a distinct type.** `Client::account` returns
  `Verified<Account>`, whose constructor is private to the crate and cannot be built unless a
  proof checked out. `Client::account_reported` is the unchecked read and returns a different
  type, so a proven value and a server-reported one cannot be confused.

Two inputs are still taken on trust, and they are the whole list: the block the config pins,
which a caller replaces by passing a previously proven anchor to `Client::connect_from`, and
the local clock, which is the only thing that catches a server replaying a genuine but stale
chain, so a clock far enough behind is reported rather than quietly passed.

## What ships today

Version 0.3.0 is the first registry release. It delivers a trust-minimized read path: connect
to a liteserver over ADNL, sync to the current masterchain head, and read a proven account,
from the Rust core or from the Node binding.

Working today:

- the TL codec, with CRC32-IEEE constructor tags,
- the TON cell model and the bag-of-cells codec,
- the block and account structures decoded from cells, and Merkle-proof verification,
- ADNL over TCP: the handshake, session-key derivation, and encrypted stream framing,
- the liteserver query layer,
- key-block sync and the proven-read facade,
- a Node binding over the facade.

A first sync covers every key block published since the pinned one, over a thousand links
against mainnet and a couple of minutes. Saving the block it ended on turns the next run into
a single link (`Client::anchor`, `Client::connect_from`). `VERIFY_EPOCH` rises whenever the
set of things the library accepts as proven changes, so a caller can tell an API-compatible
upgrade that moved the accept-or-reject boundary from one that did not
([NET-ADR-008](docs/adr/NET-ADR-008-versioning-and-bindings.md)).

## What is ahead

The write path, sending a transaction and the wallet families behind a signer seam so key
material stays outside the library, is the next spine milestone and does not exist yet. Beyond
it: the DHT, RLDP, overlays, wider ADNL, and a local TVM that runs a get-method against proven
code and data. Until the TVM lands, a value a contract computes is not provable: a native TON
balance is a proven read, and a jetton balance, which only a get-method returns, is server-reported
([NET-ADR-003](docs/adr/NET-ADR-003-scope-and-write-path.md),
[NET-ADR-007](docs/adr/NET-ADR-007-tvm.md)).

Version 1.0.0 is the whole surface a TON client speaks plus the write path, including the TVM,
and the API freezes only when the client is complete
([NET-ADR-001](docs/adr/NET-ADR-001-purpose-and-priorities.md)). Bindings beyond Rust and Node
follow once the core reaches parity
([NET-ADR-008](docs/adr/NET-ADR-008-versioning-and-bindings.md)).

## Crate layout

The core is a flat set of workspace crates under `crates/`, each named for its directory. The
internal dependencies point one way, from the facade down to the foundations and never back,
so a consumer takes only the layer it needs
([NET-ADR-009](docs/adr/NET-ADR-009-code-structure.md)).

| Crate | Layer | Role |
|---|---|---|
| `ton-net-tl` | base | The TL codec: constructor tags, boxed and bare types. |
| `ton-net-cell` | base | The TON cell model and the bag-of-cells codec. |
| `ton-net-block` | on cell, tl | TON block and account structures decoded from cells, and proof verification. |
| `ton-net-adnl` | on tl | The ADNL transport, sans-I/O over a transport seam. |
| `ton-net-lite` | on adnl, tl | The liteserver read client. |
| `ton-net` | facade | The entry point that composes the layers below and returns a proven read. |

`ton-net` is the only crate a consumer or a binding depends on. The Node binding lives in
`bindings/node` and wraps that facade; it is excluded from a default build, so a bare build
compiles the six core crates alone.

## Architecture decisions

The design is recorded as a contiguous set of Architecture Decision Records under `docs/adr/`.
NET-ADR-001 is the ground the others rest on, and NET-ADR-002 with NET-ADR-003 are the two
foundations most others build on.

| ADR | Decision |
|---|---|
| [NET-ADR-001](docs/adr/NET-ADR-001-purpose-and-priorities.md) | Purpose, and the priorities that follow. |
| [NET-ADR-002](docs/adr/NET-ADR-002-architecture.md) | One audited core, a sans-I/O seam, thin bindings. |
| [NET-ADR-003](docs/adr/NET-ADR-003-scope-and-write-path.md) | Client scope, and the write path within it. |
| [NET-ADR-004](docs/adr/NET-ADR-004-dependencies.md) | Vetted dependencies, and one copy of each crypto primitive. |
| [NET-ADR-005](docs/adr/NET-ADR-005-trust-anchor.md) | The trust anchor, and signature-checked block sync. |
| [NET-ADR-006](docs/adr/NET-ADR-006-signature-verification.md) | Validator signature verification: the signed form and the two-thirds rule. |
| [NET-ADR-007](docs/adr/NET-ADR-007-tvm.md) | The local TVM, and the differential harness that grades it. |
| [NET-ADR-008](docs/adr/NET-ADR-008-versioning-and-bindings.md) | Versioning, the verification epoch, and the binding sequence. |
| [NET-ADR-009](docs/adr/NET-ADR-009-code-structure.md) | Flat layered crates, and how a crate grows. |
| [NET-ADR-010](docs/adr/NET-ADR-010-boc-compression.md) | BoC compression behind a feature, on the untrusted boundary. |

The [architecture overview](docs/architecture.md) and the [system design](docs/design/system-design.md)
carry the same decisions at more length. The rest of the documentation covers the shape of the
work:

- [Roadmap](docs/roadmap.md): the release sequence to v1.0.0.
- [API design](docs/api-design.md): the public surface and the principles behind it.
- [Wire format](docs/protocol/wire-format.md): the TL codec, the ADNL framing, and the liteserver messages.
- [Threat model](docs/security/threat-model.md): the adversary, and what each check defends.
- [Conformance](docs/conformance.md): how correctness is held to facts the network already computed.
- [Versioning](docs/versions.md) and the [release process](docs/release-process.md).

## License

Apache-2.0. Copyright 2026 Nirapod Labs; maintained by athexweb3. The permissive license lets
any project, in any language, embed the client without a copyleft obligation. See
[LICENSE](LICENSE) and [NOTICE](NOTICE).

Contributions are accepted under the same license, certified with a
[Developer Certificate of Origin](https://developercertificate.org/) sign-off. See
[CONTRIBUTING.md](CONTRIBUTING.md).
</content>
</invoke>
