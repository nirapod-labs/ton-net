# Versioning

ton-net is one library published as many artifacts: six Rust crates on crates.io, a
Node binding on npm, and a per-platform package for every target that binding builds.
It releases on its own cadence, and a consumer pins the version it depends on
([NET-ADR-001](adr/NET-ADR-001-purpose-and-priorities.md)). This document is the concrete
form of [NET-ADR-008](adr/NET-ADR-008-versioning-and-bindings.md): how those artifacts
carry one version, what the verification epoch is and when it moves, and what forces a
breaking release.

Two numbers describe a build. They are independent and answer different questions.

- The **library version** is a single SemVer string. It answers whether an upgrade is
  API-compatible. Today it is `0.3.0`, declared once in the `[workspace.package]` table of
  the root `Cargo.toml`.
- The **verification epoch** is a monotonic integer. It answers whether an upgrade changed
  what the library accepts as proven. Today it is `1`, the value of `VERIFY_EPOCH` in
  `crates/ton-net/src/lib.rs`.

## One version, in lockstep

Every workspace crate carries the version by inheritance. The root `Cargo.toml` declares
`version = "0.3.0"` once in `[workspace.package]`, and each crate takes it with
`version.workspace = true`. This covers the six library crates (`ton-net-tl`,
`ton-net-cell`, `ton-net-block`, `ton-net-adnl`, `ton-net-lite`, `ton-net`) and the Node
binding crate (`ton-net-node`). The internal dependency edges in `[workspace.dependencies]`
pin the same version, so a crate resolves only against its own generation. There is one
changelog for the library, [`CHANGELOG.md`](../CHANGELOG.md), not one per crate.

## One version, per registry

One library is many published artifacts, and the same version maps onto each registry.

- **crates.io** carries the six library crates.
- **npm** carries the binding as the `ton-net` package, at the same version. That package
  ships no native binary of its own. It lists seven per-platform packages under the
  `@nirapod-labs` scope as optional dependencies, each pinned exact at the library version,
  so the loader installs the single native binary the host can run:
  `@nirapod-labs/ton-net-darwin-arm64`, `@nirapod-labs/ton-net-darwin-x64`,
  `@nirapod-labs/ton-net-linux-arm64-gnu`, `@nirapod-labs/ton-net-linux-arm64-musl`,
  `@nirapod-labs/ton-net-linux-x64-gnu`, `@nirapod-labs/ton-net-linux-x64-musl`, and
  `@nirapod-labs/ton-net-win32-x64-msvc`.
- The binding crate `ton-net-node` carries the library version like the rest but sets
  `publish = false`. Its registry is npm, not crates.io.

A release is tagged `v{version}`. `v0.3.0` is the first published version, the point at
which a read no longer depends on a block hash the caller has to supply. `v0.1.0` and
`v0.2.0` are tags that were never published to a registry ([`CHANGELOG.md`](../CHANGELOG.md)).

## The verification epoch

A version answers API compatibility. It cannot answer the question a caller of a verifier
actually has, which is whether an upgrade changed what the library believes is proven. The
accept-and-reject boundary moves independently of the API: it can move while every signature
stays byte-identical, and it can stay fixed across a breaking API change. `VERIFY_EPOCH` is a
separate number for that boundary.

It rises only when the boundary moves:

- a new kind of proof is accepted,
- an acceptance condition tightens or loosens,
- the rule for validator signature weight changes,
- a freshness default changes.

It does not move for wording, for performance, or for anything a caller cannot observe in an
accept or a reject. The number only increases. It is meaningless across libraries, and it is
not a version.

A caller that stored the epoch a result was verified under compares it against the current
value. When the current value is higher, the caller re-verifies rather than trusting a result
an older set of rules produced. Nothing else in the API answers that.

The boundary is pinned in the build as a transcript. `crates/ton-net/tests/epoch.rs` runs the
public verifier over one captured masterchain read and ten edits of it, and compares the
verdicts against a fixed text whose first line is the epoch. The number and the boundary it
names are one pinned pair, so moving either without the other fails the build. Each rise is
recorded in [`CHANGELOG.md`](../CHANGELOG.md) as the delta in what is now accepted and what is
now refused.

## What a breaking change is

Three kinds of change break, and any one of them forces a breaking release.

- An **API break** is a change a consumer sees in the observable surface. The release
  process refuses a release that makes one under a bump that does not admit it.
- A **behavioural break** is a move in the accept-and-reject boundary: something that
  verified now fails, or something refused now passes. This is the change the epoch tracks,
  and it is breaking whether or not the API moved with it.
- A **wire break** is a change in the bytes exchanged with the network.

SemVer here is measured against the observable API and the wire behavior, so a
proof-verification change is breaking and an internal refactor is not.

## Before 1.0.0

Before `1.0.0`, a minor release is breaking in every ecosystem ton-net ships to. Under Cargo
the leftmost non-zero field carries the break, so `0.2.0` and `0.3.0` are incompatible
generations. Under npm a caret range on a `0.x` version does not cross the next minor. The
upgrade from `0.2.0` to `0.3.0` is therefore a breaking upgrade a consumer opts into, and a
consumer pins to a minor and upgrades on purpose.

`1.0.0` is full parity, including the local TVM, and the API freezes only when the client is
genuinely complete. There is no external deadline
([NET-ADR-001](adr/NET-ADR-001-purpose-and-priorities.md)). `0.3.0` is one release along that
pre-1.0 arc.

## How a release is cut

release-plz owns the mechanism ([`release-plz.toml`](../release-plz.toml)). It decides the
version bump, opens a release pull request under the `release/` branch prefix, tags
`v{version}`, and publishes. `semver_check` refuses a release whose public API moved in a way
the bump does not admit, so an accidental breaking change fails the release rather than
reaching a registry.

The changelog is written, not generated (`changelog_update = false`). The entry is composed
into the release pull request and reviewed with it, because a commit subject does not carry
what a reader upgrading a verifier needs to know. Dependency bumps arrive through their own
pull requests and are not folded into a release (`dependencies_update = false`).

A published version is immutable in both registries. What ships under a version, the
third-party notices and the epoch among it, has to be right at publish time rather than
corrected after.
