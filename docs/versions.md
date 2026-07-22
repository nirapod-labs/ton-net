<!--
SPDX-License-Identifier: Apache-2.0
SPDX-FileCopyrightText: 2026 Nirapod Labs
-->

# Versions

Which number a given artifact carries, and what it is derived from.
[NET-ADR-009](adr/NET-ADR-009-versioning-and-binding-sequence.md) requires this mapping to
be recorded rather than inferred; this is it. The mechanics of a release are in
[release-process.md](release-process.md).

## The source of truth

The Cargo workspace version in the root `Cargo.toml`. Every other number in this
repository is stamped from it by `scripts/check-versions.mjs`, which runs with
`--fix` to write and without it in CI to check. Nothing else keeps the two
registries agreeing, because release-plz moves the Cargo side and napi moves the
npm side and neither reads the other.

## The mapping is the identity function

| artifact | registry | version |
| --- | --- | --- |
| `ton-net-tl`, `ton-net-cell`, `ton-net-adnl`, `ton-net-block`, `ton-net-lite`, `ton-net` | crates.io | the library version |
| `ton-net` | npm | the library version |
| `@nirapod-labs/ton-net-<target>`, seven of them | npm | the library version |

Six crates and eight npm packages, all carrying one number.

NET-ADR-009 allows each ecosystem its own scheme, on the grounds that ecosystems
have their own conventions. Nothing here has asked for one yet, and a mapping that
is a lookup table rather than a function has a cost the table itself hides: it
turns "which ton-net am I running" from a question with one answer into a
question that needs this file open. So the rule is **identity until an ecosystem
forces otherwise**, and if one ever does, the exception gets a row here and a line
saying which convention demanded it.

This satisfies the record NET-ADR-009 asks for. That the record is currently
trivial is the point, not an omission.

## What differs anyway: the channel, not the number

A prerelease is spelled differently by each registry even when the number is the
same, so the stamping is per-registry formatting rather than per-registry
versioning.

| registry | version string | how the channel is set |
| --- | --- | --- |
| crates.io | `0.3.0-alpha.1` | the version string carries it |
| npm | `0.3.0-alpha.1` | `npm publish --tag alpha`. Without the tag it becomes `latest`, and an install that asked for a stable version gets a prerelease |
| PyPI | `0.3.0a1` | PEP 440 spells it differently, so the stamper has to convert |
| pub.dev | `0.3.0-alpha.1` | detected from the string |
| Maven Central | `0.3.0-alpha1` | a separate repository, not a tag |

Only the first two apply today. The rest arrive with their bindings and are
recorded here so the conversion is a known cost rather than a discovery.

## Semantic versioning is measured against behavior

The version is a claim about the observable API and the wire behavior, not about
the code. A change to proof verification is breaking even when every signature
stays the same, because a caller's guarantee changed. An internal refactor is not
breaking even when it moves every file.

Before `1.0.0`, a minor release may break the API. That is stated in the readme
rather than left for a caller to discover.

## The binding version follows the core

The Node binding is built from the same commit as the crates, not from crates.io.
`ton-net-node` is `publish = false` and never reaches a registry; it compiles to
the `.node` binary that the npm packages carry. So the npm version is not an
independent number that happens to agree, it is the same number stamped outward,
and `check-versions.mjs` is what makes that true rather than aspirational.
