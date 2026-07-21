# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 Nirapod Labs

# The local equivalent of the CI gate, so a contributor can run what the build runs
# without reading the workflow. The two are kept in step by hand today; the workflow
# is still the authority on what has to pass.
#
# Needs: a stable Rust toolchain (rust-toolchain.toml selects it), `reuse` for the
# license gate (pipx install reuse), and Node for the binding.

default:
    @just --list

# Everything the hermetic CI gate runs. No network.
gate: fmt-check lint licenses test doc

# Rewrite what can be rewritten.
fmt:
    cargo fmt --all

fmt-check:
    cargo fmt --all -- --check

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
    cargo test -- --ignored --skip cold_sync

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
