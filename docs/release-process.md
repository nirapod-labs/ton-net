<!--
SPDX-License-Identifier: Apache-2.0
SPDX-FileCopyrightText: 2026 Nirapod Labs
-->

# Releasing ton-net

ton-net ships as one library across two registries. A release is a milestone, not
a commit: it takes a version from a signed git tag to published artifacts on
crates.io and npm. This document is that sequence, and the split between the two
halves of it. The governing decision is
[NET-ADR-008](adr/NET-ADR-008-versioning-and-bindings.md).

## One library, many artifacts

Every workspace crate carries a single version through workspace inheritance. The
version is declared once, in the `[workspace.package]` table of the root
`Cargo.toml`, and each crate takes it with `version.workspace = true`. The version
today is `0.3.0`.

That one version rides every artifact the library publishes:

| Registry | Artifacts | Published |
| --- | --- | --- |
| crates.io | `ton-net-tl`, `ton-net-cell`, `ton-net-block`, `ton-net-adnl`, `ton-net-lite`, `ton-net` | six crates |
| npm | `ton-net`, plus seven `@nirapod-labs/ton-net-<target>` packages | eight packages |

Seven crate manifests carry the version: the six library crates above and the Node
binding crate `ton-net-node`. Six of the seven publish to crates.io. The binding
crate sets `publish = false` in `bindings/node/Cargo.toml` and reaches consumers
through npm instead.

On npm the version sits in eight package manifests: the main `ton-net` package and
one per-platform package for each target the binding builds. The main package lists
the seven per-platform packages as optional dependencies, pinned exact, so the
loader installs the single native binary the host can run and skips the rest.

One changelog, `CHANGELOG.md`, covers the whole library. A release is tagged
`v{version}`. Both are settled in
[NET-ADR-008](adr/NET-ADR-008-versioning-and-bindings.md); the tag name is fixed in
`release-plz.toml` as `git_tag_name = "v{{ version }}"`.

## A milestone tag is not a registry publish

Two things can happen to a version, and they are separate. A signed git tag records
the milestone. A registry publish puts the artifacts on crates.io and npm.

`v0.1.0` and `v0.2.0` are signed tags that were never published to a registry.
`v0.3.0` is the first registry release. That split is not bookkeeping: three
proof-verification soundness failures were found and fixed between the tags and the
first publish, so no published release ever carried them (`CHANGELOG.md`). A
registry publish is irreversible in both directions that matter here, crates.io
yanks but never deletes and npm deprecates but never replaces, so what ships under a
version, the third-party notices and the verification epoch among it, has to be
right at publish rather than corrected after
([NET-ADR-008](adr/NET-ADR-008-versioning-and-bindings.md)).

## The split of authority

Four pieces do the work, each with one job:

- `.github/workflows/release-plz.yml` opens the release pull request. It does not
  tag and it does not publish.
- The maintainer signs and pushes the tag by hand.
- `.github/workflows/release.yml` publishes the tagged version to crates.io and npm.
- `.github/workflows/build-binding.yml` compiles the per-platform binaries the npm
  publish uploads.

The decision to release and the act of releasing are reviewed separately. A merged
pull request is what authorizes a publish, rather than being one.

## Cutting a release

### 1. Write the changelog entry

The changelog is written by hand, not generated: `release-plz.toml` sets
`changelog_update = false`. Generated from commit subjects, an entry reads "check a
block proof chain", which tells a reader upgrading a verifier nothing about whether
they were exposed to anything. The entry that earns its place says what the change
means. The next release accumulates under the `[Unreleased]` heading of
`CHANGELOG.md` as the work lands, and becomes the version's section when the release
is cut.

If the release moves what the library accepts as proven, `VERIFY_EPOCH` rises and
the entry records the delta in what is now accepted and what is now refused. This is
the one place a consumer reads before upgrading, so a moved accept-or-reject boundary
is stated there ([NET-ADR-008](adr/NET-ADR-008-versioning-and-bindings.md)).

### 2. Open the release pull request

Trigger the release-plz workflow (`.github/workflows/release-plz.yml`, on
`workflow_dispatch`). It runs on a manual trigger rather than on every push, because
a release is a milestone: on a push trigger it opened a release for every step of a
milestone in progress, naming a version nobody intended to publish.

The workflow reads the conventional commits since the last tag, works out the
version, and moves the Cargo side of the version. It runs `cargo-semver-checks`,
which refuses a bump the public API does not admit. That check is effective only
because the workflow installs `cargo-semver-checks` on PATH; without it, release-plz
skips the check and only warns. The workflow pins both tools:
`release-plz@0.3.160` and `cargo-semver-checks@0.49.0`.

The pull request carries the version bump and nothing else. `release-plz.toml` sets
`dependencies_update = false`, so a dependency sweep does not ride in on a release;
dependency bumps arrive through their own pull requests, from dependabot, where they
are reviewed as the changes they are ([NET-ADR-004](adr/NET-ADR-004-dependencies.md)).
The branch is prefixed `release/` (`pr_branch_prefix`).

Version consistency across the two registries is held by
`scripts/check-versions.mjs`, whose source of truth is the Cargo workspace version
read through `cargo metadata`. Its `--fix` stamps that version across the eight npm
manifests and the lockfile; its default mode reports drift and fails. The workflow's
last step runs it to prove one version sits in all seven crates and all eight
packages before anyone signs a tag over it.

`release-plz.toml` also sets `git_tag_name` and `git_release_enable = true`, which
the `release-plz release` subcommand would honor. This repository runs only
`release-plz release-pr`, so release-plz opens the pull request and stops. The tag
and the GitHub release are made in the steps below, not by release-plz.

Merging the pull request is the review step that authorizes the release.

### 3. Refresh the third-party notices

The npm tarballs carry `THIRD-PARTY-LICENSES.md`. The `.node` binary links its whole
dependency tree in, so each tarball redistributes many other projects, and an npm
consumer has no `Cargo.toml` in which to find their licenses. Regenerate the notices
from the dependency graph and commit the result before the tag. `just notices`
regenerates them (`cargo about`); `just notices-check` confirms the committed file
still matches the tree. This runs before a release specifically because an npm
tarball cannot be replaced once published, so notices that no longer describe what
ships cannot be corrected after the fact.

### 4. Sign and push the tag

The maintainer signs an annotated tag named `v{version}` with GPG and pushes it. The
tag is cut by hand rather than by a runner on purpose. The existing tags are GPG
signed by the maintainer, and a runner cannot reproduce that without holding the
signing key, which is the long-lived credential this whole arrangement exists to
avoid. A job that tagged from a runner would quietly replace a signed tag with an
unsigned one, and the version after would be the first whose provenance nobody could
verify (`.github/workflows/release-plz.yml`).

The release-plz workflow's final step is a reminder rather than an action: it checks
whether the declared version is already tagged, and if not, prints that the version
is declared and untagged and that signing and pushing the tag is what releases it.

### 5. The automated publish

Pushing a `v*` tag starts `.github/workflows/release.yml`, which runs four jobs in
order.

- **gate** re-runs the full offline gate (`just gate`) and confirms the tag matches
  the declared version (`scripts/check-versions.mjs`). The tag is not evidence the
  tree is good: the commit it points at may never have had a full run, and
  publishing is irreversible, so the gate runs again here rather than being assumed.
- **crates** publishes the six library crates to crates.io in dependency order:
  `ton-net-tl`, `ton-net-cell`, `ton-net-adnl`, `ton-net-block`, `ton-net-lite`,
  `ton-net`. crates.io resolves a dependency at publish time, so a crate goes out
  only after the crates it needs. `cargo publish` blocks until the version it
  uploaded is visible in the index, which is exactly the wait the next crate needs,
  so nothing sleeps between them. `--no-verify` is deliberately absent: each package
  is built from the tarball that will ship, which is the last chance to catch a crate
  that compiles in the workspace but not on its own.
- **npm** finds the `build-binding.yml` run for the same commit, downloads the
  binaries it produced, places each in its platform package, and runs
  `bindings/node/scripts/check-package.mjs`. It then publishes the seven platform
  packages first and the main package last, each with `--access public
  --provenance`. Platform packages go first because the main package resolves them as
  optional dependencies at install time, so they must exist before it names them.
- **announce** creates the GitHub release, taking its notes from the version's
  section of `CHANGELOG.md` rather than composing them again, so the release notes
  and the changelog cannot drift apart.

## The human gates

Two points require a person, by design.

- Merging the release pull request authorizes the release. A tag is not pushed until
  the pull request that declared the version has merged.
- The `crates` and `npm` jobs run in the `release` GitHub environment, which both
  registries scope their trusted publishers to. With a required reviewer on that
  environment, the OIDC token cannot be minted until a person approves the run, so
  pushing a tag is not by itself enough to publish. For a library whose whole claim
  is that it verifies rather than trusts, a human gate on its own supply chain is
  proportionate (`.github/workflows/release.yml`).

The required reviewer is a repository setting rather than a file in the tree.

## Trusted publishing, and the one-time bootstrap

Neither publish job holds a long-lived credential. Each exchanges the run's OIDC
assertion for a registry token good for minutes: crates.io through
`crates-io-auth-action`, npm through its provenance flow. Nothing reads a secret,
and none exists to leak.

A trusted publisher can only be attached to a crate or package that already exists,
and neither registry has a pending-publisher equivalent, so the first release cannot
use this path. The bootstrap is a one-time sequence:

1. Publish the first version of the six crates and eight packages by hand, with a
   token.
2. Configure the fourteen trusted publishers against `release.yml`.
3. Revoke the tokens.

Every release after that is the workflow. Until the bootstrap has happened,
`release.yml` runs and stops at the first publish, reporting that the trusted
publisher is not configured rather than reaching for a secret that should not exist.
Version `0.3.0` is the release designated for this bootstrap
(`.github/workflows/release.yml`,
[NET-ADR-008](adr/NET-ADR-008-versioning-and-bindings.md)).

## The binaries a release uploads

`.github/workflows/build-binding.yml` compiles the Node binding for every platform
it publishes to. It does not publish. It runs on a `v*` tag, so a release has its
artifacts, and weekly, so a target that stops building is found in a quiet week
rather than during a release.

Each of the seven targets builds natively on a runner of its own architecture. The
two musl targets build inside Alpine, because a musl target linked on a glibc host is
a musl artifact in name only. The workflow then proves the binaries are worth
shipping before they ship: a smoke job loads a built binary and reaches a live
liteserver with it, and a separate job loads each musl binary on musl. The `npm` job
in `release.yml` publishes what this matrix produced for the same commit rather than
rebuilding, so the binaries that were loaded and smoke tested are the binaries that
reach a consumer.

## What guards a release

Most of a release is the confirmation of checks that were already green. The same
guards run continuously in CI (`.github/workflows/ci.yml`) on every push and pull
request, and again on the tagged commit.

- **`cargo-semver-checks`** refuses an observable API break under a bump that does
  not admit it (`release-plz.toml` `semver_check`, enforced in `release-plz.yml`).
- **`scripts/check-versions.mjs`** holds one version across the crates, the eight npm
  manifests, and the lockfile, with the Cargo workspace version as the source of
  truth. It runs in the release-plz workflow, in the release gate, and in CI's
  `release-ready` job alongside `cargo publish --dry-run --workspace`.
- **`bindings/node/scripts/check-package.mjs`** asserts each tarball carries its
  license and notices, that the main package does not ship the Rust sources or a
  compiled binary, and that every platform package is wired as an optional dependency
  of the main one. It runs before publish because a tarball cannot be replaced.
- **`just notices-check`** confirms `THIRD-PARTY-LICENSES.md` still describes the
  dependency tree the tarballs ship.
- **`build-binding.yml`** smoke-loads the binaries against a live liteserver, and
  loads both musl binaries on musl, before any of them ship.
- **The release gate** re-runs the whole offline gate on the tagged commit, because
  the tag alone does not prove the tree ever passed.

## What counts as a breaking release

Three things break, and any one forces a breaking release. An API break is a change
a consumer sees in the observable surface, and the release process refuses it under
an inadmissible bump. A behavioral break is a move in the accept-or-reject boundary,
where something that verified now fails or something refused now passes; this is the
change the verification epoch tracks, and it is breaking whether or not the API moved
with it. A wire break is a change in the bytes exchanged with the network. SemVer
here is measured against the observable API and the wire behavior, so a
proof-verification change is breaking and an internal refactor is not.

Before `1.0.0`, every minor release can break, under both Cargo's leftmost-non-zero
rule and npm's `0.x` caret range, so a consumer pins to a minor and upgrades on
purpose ([NET-ADR-008](adr/NET-ADR-008-versioning-and-bindings.md)).

## Pre-release versions

No pre-release has shipped. The registries spell a pre-release differently: crates.io
takes `0.3.0-alpha.1`, npm takes the same string but needs `--tag alpha` to keep it
off the `latest` tag, and a future PyPI target would want `0.3.0a1`.
`scripts/check-versions.mjs` is where that per-registry mapping lives; only the npm
side exists today. A pre-release flow is where that mapping is completed.

## Reaching a new language

Node is the only binding today. The core reaches parity carrying one binding, and the
browser, Python, Swift, and Kotlin bindings follow after
([NET-ADR-008](adr/NET-ADR-008-versioning-and-bindings.md)). Each new binding adds a
registry, and its version mapping goes in `scripts/check-versions.mjs` alongside the
npm one. A binding takes the library version like the rest and publishes at the same
number, so one version continues to name the whole library.
