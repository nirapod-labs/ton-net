# ton-net

A TON network client written once in Rust, verified against validator signatures, and bound
natively into other languages.

[![crates.io](https://img.shields.io/crates/v/ton-net.svg?logo=rust)](https://crates.io/crates/ton-net)
[![docs.rs](https://img.shields.io/docsrs/ton-net?logo=docsdotrs)](https://docs.rs/ton-net)
[![npm](https://img.shields.io/npm/v/ton-net.svg?logo=npm)](https://www.npmjs.com/package/ton-net)
[![Apache-2.0](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)

```toml
[dependencies]
ton-net = "0.4"
```

```bash
npm install ton-net
```

Before 1.0.0 a minor is breaking in both ecosystems, so a consumer opts into each one. The
[changelog](CHANGELOG.md) names what moved.

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

Two things ship. A trust-minimized read path: connect to a liteserver over ADNL, sync to the
current masterchain head, and read a proven account, from the Rust core or the Node binding.
And the cell engine that read is built on, which stands on its own as a TON cell library for a
program that never opens a socket.

The read path:

- the TL codec, with CRC32-IEEE constructor tags,
- ADNL over TCP: the handshake, session-key derivation, and encrypted stream framing,
- the liteserver query layer,
- the block and account structures decoded from cells, and Merkle-proof verification,
- key-block sync and the proven-read facade,
- a Node binding over the facade.

The cell engine, in the `cell` module:

- cells and their identity, with `Builder` and `Slice` as a pair, so what one writes the other
  reads back in the form it went in,
- three dictionary shapes: `Dict`, `AugDict` for `HashmapAug`, where each node carries a
  summary of the subtree under it, and `PfxDict` for prefix maps,
- Merkle proofs and updates, built here and anchored in `proof`: `create_proof`,
  `create_update`, `apply_update`, `combine_updates`, `validate_update`, and `virtualize` with
  the pruned-branch rules around it,
- `UsageTree`, which records the cells a read touched, so a proof can be cut to them,
- the bag-of-cells codec, including `LazyBoc` for a subtree opened on demand and `BocView` for
  a bag read without building cells,
- `base64_encode`, `base64_decode`, `hex_encode` and `hex_decode`, the spellings a serialized
  bag and a cell hash travel in.

The crate root re-exports the cell types its own methods answer with, so a caller can name
what `Cell::parse` or `Client::account_state` hands back without reaching for a module. It
stops there on purpose: the augmented and prefix dictionaries, the proof builders and the
streaming readers are reachable from no method the root returns, so a consumer whose need is
the cell engine itself names `ton_net::cell` and has all of it rather than finding half of it
at the root. Taking the crate with `default-features = false` drops tokio and the socket and
keeps the cell engine, the typed structures, the proof engine, the ADNL handshake and frame
crypto, `Verified`, address parsing and the config reader.

A first sync covers every key block published since the pinned one, over a thousand links
against mainnet and a couple of minutes. Saving the block it ended on turns the next run into
a single link (`Client::anchor`, `Client::connect_from`). `VERIFY_EPOCH` rises whenever the
set of things the library accepts as proven changes, so a caller can tell an API-compatible
upgrade that moved the accept-or-reject boundary from one that did not
([NET-ADR-008](docs/adr/NET-ADR-008-versioning-and-bindings.md)). It is 2 today.

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

## Module layout

The core is one crate, `ton-net`, whose source is `core/src`. Its layers are flat modules
declared in `core/src/lib.rs`. The edges between them point one way, from the facade down to
the foundations and never back, so a build stops where the consumer does
([NET-ADR-009](docs/adr/NET-ADR-009-code-structure.md)).

| Module | Layer | Role |
|---|---|---|
| `tl` | base | The TL codec: constructor tags, boxed and bare types. |
| `cell` | base | The TON cell model and the bag-of-cells codec. |
| `tlb` | on cell | TON block and account structures decoded from cells. |
| `proof` | on cell, tl, tlb | Merkle-proof, chain and validator-signature verification. |
| `adnl` | on tl | The ADNL transport, sans-I/O over a transport seam. |
| `lite` | on adnl, tl | The liteserver read client. |
| root, `client` | facade | The entry point that composes the layers below and returns a proven read. |

The direction is not left to a manifest to imply. `scripts/check-layers.mjs` reads the source
text of `cell`, `tlb`, `proof` and `tl` and refuses any of them naming a layer above, naming
tokio or getrandom, or reaching the socket, the filesystem, the process, the environment, a
thread or a clock, which are the reaches no dependency graph can see because `std` needs no
edge. It asserts the edges below them in the same reading, so a check that has stopped
matching fails rather than passing quietly.

`ton-net` is the only crate a consumer or a binding depends on. The Node binding lives in
`bindings/node` and wraps it; the binding is excluded from a default build, so a bare build
compiles the library crate alone.

## Architecture decisions

The design is recorded as a contiguous set of Architecture Decision Records under `docs/adr/`.
NET-ADR-001 is the ground the others rest on, and NET-ADR-002 with NET-ADR-003 are the two
foundations most others build on.

A record describes the tree as it stood when the decision was taken, and it is not rewritten
when the tree catches up. What was built lands in a `Since acceptance` section at the end,
with a pointer to it under the title, so the record of what was known then survives alongside
the correction. Reversing a decision is the other instrument, and that is `supersedes` and
`superseded-by` in the frontmatter.

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
| [NET-ADR-011](docs/adr/NET-ADR-011-identity-and-trust.md) | What a cell's identity is, and the barrier a trusted hash may not cross. |
| [NET-ADR-012](docs/adr/NET-ADR-012-scale-contract.md) | What the cell engine promises at scale. |

The [architecture overview](docs/architecture.md) and the [system design](docs/design/system-design.md)
carry the same decisions at more length. The rest of the documentation covers the shape of the
work:

- [Roadmap](docs/roadmap.md): the release sequence to v1.0.0.
- [API design](docs/api-design.md): the public surface and the principles behind it.
- [Wire format](docs/protocol/wire-format.md): the TL codec, the ADNL framing, and the liteserver messages.
- [Threat model](docs/security/threat-model.md): the adversary, and what each check defends.
- [Conformance](docs/conformance.md): how correctness is held to facts the network already computed.
- [Fuzzing](docs/fuzzing.md): the targets on the decode boundary, and how to run them.
- [Versioning](docs/versions.md) and the [release process](docs/release-process.md).

## License

Apache-2.0. Copyright 2026 Nirapod Labs; maintained by athexweb3. The permissive license lets
any project, in any language, embed the client without a copyleft obligation. See
[LICENSE](LICENSE) and [NOTICE](NOTICE).

Contributions are accepted under the same license, certified with a
[Developer Certificate of Origin](https://developercertificate.org/) sign-off. See
[CONTRIBUTING.md](CONTRIBUTING.md).
