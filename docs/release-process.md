# Release process

How a version of ton-net reaches crates.io and npm. The decisions behind it are in
[NET-ADR-009](adr/NET-ADR-009-versioning-and-binding-sequence.md); this is the sequence.

A milestone tag and a registry publish are separate acts. Every milestone is
tagged; a registry release is gated on the trust boundary, which v0.3.0 is the
first version to cross.

## What holds the version together

The library ships as six crates on crates.io and eight packages on npm, built from
one commit through two toolchains that do not read each other. release-plz moves
the Cargo side, napi moves the npm side.

The Cargo workspace version is the source of truth. `scripts/check-versions.mjs`
stamps it outward with `--fix` and checks it in CI without. Nothing else keeps the
two registries agreeing, so a release that skips it publishes two artifacts
claiming to be the same library at different numbers.

Which number each artifact carries, and how a prerelease is spelled differently by
each registry even when the number is the same, is in [versions.md](versions.md).

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
5. `just notices-check` passes. The notices are generated from the dependency
   graph and staged into all eight npm tarballs, and an npm version can be
   deprecated but never replaced, so this is the last moment a wrong one can be
   corrected. CI runs the same check on every push and daily.
6. `just check-config` passes, and `just test-snapshot` passes with its output read
   rather than only its exit code.

   These answer different questions, and the difference decides whether there is
   any work to do. `check-config` compares the bundled configuration against the
   one TON publishes, which is the only part a refresh can fix. `test-snapshot`
   reports how many bundled liteservers answer and how far the pinned block sits
   behind the head, and neither of those is drift in this copy: the pinned block
   is the one TON publishes, TON rotates it rarely, and a lag of tens of millions
   of blocks is the age of the upstream anchor. A refresh against an unchanged
   upstream copies the same bytes back, dead liteservers included.

   Refreshing, when `check-config` reports a difference, means taking the
   published configuration into `crates/ton-net/src/mainnet.config.json`. If the
   init block moved, that moves the default trust anchor, so the walk from the new
   pinned block has to be run before the release, not after: `just test-sync`.
7. The binding matrix is green on a dispatch from `main`, including both jobs that
   load a musl binary on musl. That workflow runs on a tag, a schedule and a
   dispatch, so no ordinary commit exercises it, and the first time it ran it
   failed on three of seven targets.

   Read the two musl legs rather than only the overall result. An npm version can
   be deprecated but never replaced, so a musl package that cannot load is
   permanent, and a musl binary that builds is not one that runs.

## Cutting it

release-plz opens a release pull request carrying the version bump. On that
branch:

1. Rename `## [Unreleased]` to the version and date, and open a fresh empty
   `[Unreleased]`. Update the comparison links at the bottom.
2. Run `node scripts/check-versions.mjs --fix` so the npm manifests and the pinned
   optional dependencies follow the bumped crates.
3. Push. CI has to be green, including the version check and the publish dry-run.

Merging the pull request does not release anything. The tag does, and the tag is
signed by hand:

    gp athexweb3 git tag -s "v0.3.0" -m "ton-net v0.3.0"
    gp athexweb3 git push origin "v0.3.0"

A runner cannot sign that tag without holding the signing key, which is the
long-lived credential trusted publishing exists to remove, so signing stays with
the maintainer. It also means signing the tag and authorizing the publish are one
act rather than two that can drift apart: the push is what wakes `release.yml`.

## Which file does what

Two workflows, split so that deciding to release and releasing are separate acts
and a merge authorizes a publish rather than being one.

- **`.github/workflows/release-plz.yml`** opens and updates the release pull
  request on every push to `main`. It reaches no registry, holds no credential, and
  does not tag. `git_release_enable` in `release-plz.toml` therefore governs a
  subcommand nothing runs.
- **`.github/workflows/release.yml`** wakes on the tag. It reruns the whole gate,
  because a tag is not evidence that the commit under it ever had a full run and
  crates.io yanks but never deletes. Then it publishes the six crates bottom up,
  then the platform packages, then the main package, then writes the GitHub
  release from the changelog section for that version. If the section is still
  called `[Unreleased]` the job fails, which is the reminder to move the heading.

Both publish jobs run in a GitHub environment named `release`, which is also what
the trusted publishers are scoped to. Put a required reviewer on that environment:
it means minting the OIDC token needs a person, so pushing a tag is not by itself
enough to publish. That environment has to exist before the first automated run,
and it is the one piece of setup neither workflow can do for itself.

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
publisher, so the first version of each of the six crates and each of the eight npm
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

## What is signed, and what is only attested

Three different things, and only the first is a signature in the sense the word
usually carries:

- **The git tag** is GPG signed by the maintainer, and `git tag -v` checks it. It
  covers the commit, so it is the one link that says which source a release was cut
  from.
- **The npm tarballs** carry a Sigstore provenance attestation, produced by
  `--provenance` and checkable with `npm audit signatures`. It is not a maintainer
  signature: it is GitHub attesting that this tarball came out of this workflow at
  this commit, which is a different and weaker claim, and a useful one.
- **The crates** carry nothing. crates.io has no package signing, so there is no
  GPG option to take and none is implied. The trusted publisher is the whole
  provenance story on that side: what it establishes is that a version was uploaded
  by a run of a named workflow in a named repository, and nothing about who wrote
  it.

The GitHub release is not itself signed. It names the tag, which is.

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
