# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 Nirapod Labs

# The local equivalent of the CI gate, so a contributor can run what the build runs
# without reading the workflow. The two are kept in step by hand today; the workflow
# is still the authority on what has to pass.
#
# Needs: a stable Rust toolchain (rust-toolchain.toml selects it), `reuse` for the
# license gate (pipx install reuse), `taplo` and `typos`, and Node for the binding.
#
# Markdown, YAML and JSON have no formatter here, and that is a decision rather than a
# gap. The one that was measured, dprint, reformatted fourteen files and the whole of
# what it changed was padding table cells out to an even width. That buries a real edit
# in a column of spaces at review time, which is the same reason `.gitattributes` marks
# the generated notices. JSON was already byte-for-byte what the formatter wanted, so
# it would have been a tool that found nothing and guarded what `check-package`
# already guards.

default:
    @just --list

# Everything the hermetic CI gate runs. No network.
gate: fmt-check lint typos licenses workflows versions test doc

# A moved action tag is somebody else's code in this build. Also checks that a workflow
# states what it may write and that a fork's schedule does not run it.
workflows:
    node scripts/check-workflows.mjs

# Advisories, licenses, duplicate versions and sources. Needs the advisory database, so
# unlike the rest of the gate this one reaches the network. CI also runs it daily,
# because an advisory arrives against a version that merged weeks ago.
deny:
    cargo deny check

# The crates and the npm packages ship from one commit but publish through two
# toolchains that do not read each other, so nothing but this keeps them in step.
versions:
    node scripts/check-versions.mjs

# Regenerates the notices the npm tarballs carry. The `.node` links its whole
# dependency tree in, so publishing it redistributes eighty-odd other projects and
# an npm consumer has no Cargo.toml to find their licenses in. Run it when the
# dependency graph moves; the accepted set mirrors deny.toml.
notices:
    cargo about generate --manifest-path bindings/node/Cargo.toml about.hbs -o THIRD-PARTY-LICENSES.md

# Whether the committed notices still describe the tree they claim to. Regenerating is
# deterministic for a fixed cargo-about, so a diff means the tree moved under the file,
# or the generator did; CI pins the generator to tell the two apart. Like `deny`, this
# reaches the network. Run it before a release: the notices ship inside eight npm
# tarballs and cannot be corrected after one, which release-process.md covers.
notices-check: notices
    git diff --stat --exit-code THIRD-PARTY-LICENSES.md

# The sans-I/O core, on a target with no threads, no sockets and no clock. The
# transport crates are expected to fail this until the browser transport lands.
wasm:
    cargo build --target wasm32-unknown-unknown -p ton-net-tl -p ton-net-cell -p ton-net-block

# What the hot paths cost, over committed fixtures, so it runs offline.
bench:
    cargo bench -p ton-net-cell --bench cells
    cargo bench -p ton-net-block --bench verify

# Removes one check at a time and reruns the suite, which answers the question a
# passing suite cannot: would a test notice. Slow, so it is a scheduled job in CI.
mutants:
    cargo mutants -p ton-net-cell -p ton-net-block --timeout 120

versions-fix:
    node scripts/check-versions.mjs --fix

# What crates.io would accept. Cargo resolves the inter-crate dependencies through
# a temporary local registry, so this works before the first crate is published.
publish-check:
    cargo publish --dry-run --workspace

# Rewrite what can be rewritten. Rust and TOML have formatters; the markdown and the
# workflows are left alone on purpose, see `notes` below.
fmt:
    cargo fmt --all
    RUST_LOG=warn taplo fmt

fmt-check:
    cargo fmt --all -- --check
    RUST_LOG=warn taplo fmt --check

# Spelling, over comments and documentation as much as over code. In a repository
# where the argument for a check is written beside it, prose is the larger surface and
# nothing else reads it. Fixtures and the generated notices are excluded in _typos.toml.
typos:
    typos

# Install the git hooks. They run the fast checks on staged files only; lefthook.yml
# says which and why.
hooks:
    lefthook install

lint:
    cargo clippy --all-targets -- -D warnings
    cargo clippy -p ton-net-node --all-targets -- -D warnings

# Every file carries a copyright holder and a license identifier.
licenses:
    reuse lint

test:
    cargo test

doc:
    RUSTDOCFLAGS="-D warnings" cargo doc --no-deps
    RUSTDOCFLAGS="-D warnings" cargo doc --no-deps -p ton-net-node

# Reaches a live mainnet liteserver. Each test skips if its server is unreachable.
test-live:
    cargo test -- --ignored --skip cold_sync --skip snapshot

# How much of the bundled mainnet snapshot the network still recognises: how many of its
# liteservers answer, and how far its pinned block has fallen behind. Dials every server,
# so it takes about a minute. Neither number is drift in this copy; for that, see
# check-config.
test-snapshot:
    cargo test -p ton-net --test snapshot -- --ignored --nocapture

# Whether the bundled configuration still matches the one TON publishes. This is the
# question a refresh can answer, unlike the lag test-snapshot reports, which is the age of
# the upstream anchor.
check-config:
    node scripts/check-config-drift.mjs

# The full walk from the block the config pins. Minutes, and tens of megabytes.
test-sync:
    cargo test -- --ignored cold_sync

# The floor each manifest declares, passed explicitly so rust-toolchain.toml does
# not quietly substitute stable and turn this into a second check of the default.
msrv:
    cargo +1.85.0 build
    cargo +1.88.0 build -p ton-net-node

node-build:
    cd bindings/node && npx napi build --platform

node-test: node-build
    cd bindings/node && node test.mjs

# The spikes are standalone projects with their own lockfiles, outside the
# workspace, so no workspace-wide command reaches them.
spikes:
    #!/usr/bin/env bash
    set -euo pipefail
    for manifest in spikes/*/Cargo.toml; do
        echo "== ${manifest%/Cargo.toml} =="
        cargo fmt --manifest-path "$manifest" --check
        cargo clippy --manifest-path "$manifest" --all-targets -- -D warnings
    done
