# Contributing to ton-net

ton-net reads the TON network without trusting the server it reads from. Most of
the code exists to check something a liteserver said, over bytes that arrive from
the open internet and may be hostile. That shapes what a good contribution looks
like here more than any style rule does.

## Before writing code

Open an issue first for anything beyond a small fix. The design is recorded in
[docs/adr](docs/adr) and the milestones in [docs/roadmap.md](docs/roadmap.md); a
change that contradicts a decision there needs the decision revisited, not worked
around.

Two rules carry more weight than the rest:

- **A security property is claimed only where the code proves it.** Documentation
  that says a value is verified must point at the check that verifies it. A
  comment asserting a guarantee the code does not enforce is a defect, and it is
  reviewed as one.
- **A parser does not panic on hostile input.** Anything reachable from network
  bytes returns an error instead. An `unwrap` on a length, an index into a slice
  whose bounds came off the wire, or arithmetic that can overflow are all bugs
  even when no test reaches them yet.

Do not report a vulnerability in an issue or a pull request, where it is public
from the moment it is filed. Use private reporting, under the repository's
Security tab, so a fix can ship before the details do.

## Development

The workspace needs a stable Rust toolchain. The core crates build on 1.85; the
Node binding needs 1.88, which is what napi-rs 3 requires.

```
cargo fmt --all -- --check
cargo clippy --all-targets -- -D warnings
cargo test
RUSTDOCFLAGS="-D warnings" cargo doc --no-deps
reuse lint
```

All five run in CI and all five must pass.

Tests that reach a live mainnet liteserver are marked `#[ignore]` so the default
run stays offline and deterministic. Run them with `cargo test -- --ignored`. Each
skips rather than fails when its server is unreachable, so a rotated liteserver
does not break a build, and a real protocol regression still does. The full walk
from the pinned init key block is the slowest of them and is filtered out of the
usual run with `--skip cold_sync`.

The Node binding lives in `bindings/node` and builds with `npx napi build
--platform`. Its gate test is `node test.mjs`.

## The library does not panic

Every library crate denies `unwrap`, `expect`, `panic`, `unreachable`, `todo` and
slice indexing. Bytes reach these crates from a liteserver nobody vouches for, and
a panic in a decoder ends the process that embedded the library, so a failure has
to come back as an error a caller can handle.

Clippy exempts a test, where an unwrap is the assertion. In library code, reach for
`get`, `first_chunk`, `split_at_checked`, a slice pattern, or an error variant. When
the compiler already knows the case cannot happen, say so with `#[expect(..., reason
= "...")]` and a comment giving the argument; an audited exemption is a fine outcome,
an unexplained one is not.

Arithmetic is not in the set. Every count these formats carry is bounded before it
is used and each subtraction sits within a few lines of its guard, so denying it
would bury the real bounds under `checked_sub`. That makes an overflow the reviewer's
job: when a length comes off the wire, check it before it is multiplied.

## Tests

A test name is a sentence saying what must hold, not a label for what it calls:

```rust
fn a_pruned_branch_may_not_carry_references() { ... }
fn a_clock_behind_the_chain_is_reported_rather_than_obeyed() { ... }
```

The reason is that a failing test then states the broken property in the output,
where a name like `test_prune_1` sends the reader back into the source to find out
what broke.

A test for a guard should be checked against the guard's absence. Remove the check,
confirm the test fails, put the check back. A regression test that passes either
way is not testing anything.

## Commit messages

Conventional commits, `type(scope): subject`, imperative and lowercase, around 50
characters, no trailing period. Wrap a body at 72 columns.

Types in use: `feat`, `fix`, `refactor`, `test`, `docs`, `build`, `ci`, `chore`.
Scopes follow the crate the change lands in: `tl`, `cell`, `block`, `adnl`,
`lite`, `net`, `node`. A change spanning the workspace takes no scope.

The subject says what the change does. Add a body only when the reason is not
visible in the diff, and let it explain why rather than restate what.

## Sign-off

Every commit carries a `Signed-off-by` line certifying the
[Developer Certificate of Origin 1.1](https://developercertificate.org/):

```
git commit -s
```

The sign-off states that the contributor wrote the change or otherwise has the
right to submit it under the project's license. It is a statement about
provenance; it transfers nothing.

## License headers

Every source file begins with:

```rust
// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Nirapod Labs
```

with the comment syntax the file format uses. Formats that cannot carry a comment
are declared in [REUSE.toml](REUSE.toml) instead. `reuse lint` fails on a file
that carries neither.

Files that came from somewhere else keep the notice they arrived with. The
mainnet network configuration is the one such file today and is declared
separately; a sweep must never overwrite an entry like it.

## License of contributions

ton-net is Apache-2.0. Under section 5 of that license, a contribution submitted
for inclusion is under the same terms unless it states otherwise, so a
contribution needs no separate agreement. The sign-off above records provenance on
top of that; it is not a copyright assignment and none is asked for.
