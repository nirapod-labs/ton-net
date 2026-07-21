# Release process

How a version of ton-net reaches crates.io and npm. The decisions behind it are in
[NET-ADR-004](adr/NET-ADR-004-bindings-and-versioning.md); this is the sequence.

A milestone tag and a registry publish are separate acts. Every milestone is
tagged; a registry release is gated on the trust boundary, which v0.3.0 is the
first version to cross.

## What holds the version together

The library ships as six crates on crates.io and nine packages on npm, built from
one commit through two toolchains that do not read each other. release-plz moves
the Cargo side, napi moves the npm side.

The Cargo workspace version is the source of truth. `scripts/check-versions.mjs`
stamps it outward with `--fix` and checks it in CI without. Nothing else keeps the
two registries agreeing, so a release that skips it publishes two artifacts
claiming to be the same library at different numbers.

## Before the release

1. `just gate` passes, and so does the live suite: `just test-live`, plus
   `just test-sync` for the walk from the pinned block.
2. `just publish-check` passes. Cargo resolves the inter-crate dependencies
   through a temporary registry, so this works before the first crate is
   published.
3. The `## [Unreleased]` section of [CHANGELOG.md](../CHANGELOG.md) says what
   changed, in the terms a reader upgrading a client needs. A fix to a
   verification path gets a `### Security` entry saying what an attacker could
   have done, whether any published version carried it, and what now refuses it.
4. The measured numbers in the README still match. A sync benchmark that has
   drifted is a claim that has gone stale.
5. `just test-snapshot` passes, and its output is read rather than only its exit
   code. It reports how many of the bundled liteservers still answer and how far
   the pinned block has fallen behind the head. Both decay with the network rather
   than with a commit, and a published crate cannot be replaced, so a snapshot that
   had already decayed on release day is a patch release rather than a fix.

   Refreshing it means taking the current published mainnet configuration into
   `crates/ton-net/src/mainnet.config.json`. That moves the default trust anchor,
   so the walk from the new pinned block has to be run before the release, not
   after: `just test-sync`.
6. The binding matrix is green on a dispatch from `main`, including the job that
   loads a musl binary on musl. That workflow runs on a tag, a schedule and a
   dispatch, so no ordinary commit exercises it, and the first time it ran it
   failed on three of seven targets.

   Two of those are still failing and they block this release:
   [#7](https://github.com/nirapod-labs/ton-net/issues/7), the musl artifacts are
   built on a glibc host, so the x64 one carries the glibc interpreter and the
   arm64 one does not link. An npm version can be deprecated but never replaced, so
   a musl package that cannot load is permanent.

## Cutting it

release-plz opens a release pull request carrying the version bump. On that
branch:

1. Rename `## [Unreleased]` to the version and date, and open a fresh empty
   `[Unreleased]`. Update the comparison links at the bottom.
2. Run `node scripts/check-versions.mjs --fix` so the npm manifests and the pinned
   optional dependencies follow the bumped crates.
3. Push. CI has to be green, including the version check and the publish dry-run.

Merging the pull request tags the release and publishes the crates in dependency
order.

## The npm side

The binaries are built from the same commit, not from crates.io. Each target
produces one `.node`, `napi artifacts` collects them into the per-platform
packages, and `npm run prepack` stages the license and the notice into every one
of them, because each is a separate redistribution under Apache-2.0 section 4.

`npm run check-package` asserts the result before anything is uploaded. An npm
version can be deprecated but never replaced, so a tarball missing a license or
carrying the Rust sources is permanent.

Publish the per-platform packages first and the main package last. The main
package's optional dependencies name exact versions; if it lands first, an install
resolves against binaries that are not there yet.

## Credentials

crates.io, npm, PyPI and pub.dev all support trusted publishing, where the
registry accepts a short-lived OIDC token minted by the workflow and no long-lived
secret exists to leak. Use it.

It does not cover the first release. A trusted publisher is configured on a crate
or a package that already exists, and crates.io has no equivalent of PyPI's pending
publisher, so the first version of each of the six crates and each of the nine npm
packages is published by hand with a token. Only then can the registry side be
configured. That makes the first release a different act from every one after it:

1. Publish 0.3.0 by hand. Six crates in dependency order, then the per-platform
   npm packages, then the main npm package.
2. Add a trusted publisher on each: the repository, the release workflow's file
   name, and the environment if the workflow uses one.
3. Revoke the tokens used in step one. They have done their only job, and a token
   that outlives its purpose is the thing trusted publishing exists to remove.

From then on a release workflow mints its own token per run. It needs
`id-token: write`, `rust-lang/crates-io-auth-action` for the crates side, and on
the npm side a CLI new enough to speak OIDC, which also attaches provenance
without being asked.

Maven Central is the other exception and has no OIDC path at all: it needs a GPG
signing key and a portal token held as repository secrets. That is the one place a
long-lived credential stays unavoidable, and it arrives with the Kotlin binding
rather than now.

## After it lands

- Install the published package in a clean container and run an example against
  mainnet. What was built is not what was published until something has installed
  what was published.
- Check that docs.rs built every crate. A crate whose documentation failed to
  build is a crate nobody can read.
- The release notes are the changelog entry. They do not get written twice.

## If a publish fails halfway

crates.io does not allow deleting a version, only yanking it. A run that dies
between the third and fourth crate leaves three published and three not.

Do not retry from the beginning. Publish the remaining crates in order at the same
version, then verify with a fresh `cargo add` in an empty project. Yanking is for
a version that is wrong, not for one that is merely incomplete, since yanking the
first three would break anyone who resolved them in the meantime.
