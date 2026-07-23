---
id: NET-ADR-011
title: Structure follows visibility, not file length
status: accepted
date: 2026-07-23
supersedes: none
superseded-by: none
---

# NET-ADR-011: Structure follows visibility, not file length

## Context

The workspace is seven crates: 11,655 lines of source, 4,937 of tests and 125 of
benchmarks. The TVM alone is expected to be several times the current source, and
NET-ADR-001 commits to six binding targets where one exists today.

Two gaps prompted this.

[architecture.md](../architecture.md) documents a target layout of `core/tl/`,
`core/cell/`, `core/proof/`, `core/sync/` and `core/tvm/`. That layout was never
built. What exists is a flat `crates/ton-net-*` beside a virtual manifest, which
is the better of the two, and the document still governs where the TVM, the DHT
and five more bindings are expected to land.

Nothing records how a crate should grow inside. Every crate is a flat `src/*.rs`:
40 files and no directories anywhere in the workspace.

Three Rust codebases of the shape this one is heading toward were measured, at
the commit each was cloned from. libsignal is the closest comparison, being a
Rust core with per-language bindings and the same class of security surface.

| | src files | median | p90 | max | over 1000 lines | `mod.rs` | dirs under `src/` |
|---|---|---|---|---|---|---|---|
| rust-analyzer, 572k lines | 912 | 321 | 1370 | 11893 | 16% | 9 | 106 |
| libsignal, 180k lines | 496 | 160 | 818 | 3660 | 7% | 10 | 177 |
| matrix-rust-sdk, 352k lines | 668 | 268 | 1249 | 5343 | 14% | 122 | 130 |
| ton-net, 17k lines | 40 | 283 | 588 | 987 | 0% | 0 | 0 |

Two things follow. This crate's files are ordinary in length and unusually free
of long ones, so length is not the problem it is often taken for. And of the four,
only this one has no module tree at all.

One property of the language decides the rest. A child module reads its parent's
private items, including private types and private fields; a sibling module gets
`error[E0603]` and has to be handed `pub(crate)`. Both were compiled to confirm
it. So a module tree that grows downward keeps the visible surface where it was,
and one that grows sideways widens it permanently, for every item and forever.
That is why the shape of a split matters more than the fact of one.

## Decision

### Crates

A new crate needs at least one of these to be true:

- it is a layer, in that something depends on it and it depends on strictly less
- it is a platform or capability boundary, as the DHT is for a browser target
  that cannot reach it, or the TVM is for a consumer who wants proofs and no
  interpreter
- its build time is worth isolating on its own
- it is useful to someone who wants none of the rest

Tidiness is not on the list. Every crate is another registry publication moving
in version lockstep with the others, and v0.3.0 already ships fourteen artifacts.
On the measured comparison this workspace is the most finely divided of the four,
at about 2,400 lines per crate against libsignal's 6,700 and rust-analyzer's
16,000, so the count is ahead of the size rather than behind it.

Crates stay flat under `crates/`, and a crate is named exactly for the directory
it lives in. Nesting them under a grouping directory would break that, and the
grouping is the first thing to go stale.

### Modules

A module that outgrows its file becomes `foo.rs` beside a `foo/` directory, and
what moves out becomes its children. Never a sibling.

This is the rule the privacy property above pays for. `read_label` and `Walk` stay
private to `dict` when `dict/aug.rs` is a child of it, and would each need
`pub(crate)` if `aug.rs` sat next to `dict.rs`. The split also narrows: whatever
`dict/aug.rs` defines is private to `aug` and invisible to the rest of `dict`, so
a downward split reduces the surface while raising the file count.

The parent keeps the general case and the children take the specialisations. It
is not an index. Across rust-analyzer's 84 parent files the median is 577 lines
and only 9% are under 50.

`foo.rs` and not `foo/mod.rs`. rust-analyzer carries 9 `mod.rs` across 912 files
and libsignal 10 across 496; the alternative leaves an editor full of tabs with
one name.

There is no maximum file length, and none should be introduced. Length is a
symptom that reports on cohesion badly: a file is too long when a reader has to
hold two vocabularies at once, and that has no line count. The signal to split is
that a group of items is used by one part of the file and no other, because that
is the split that narrows something. Splitting a cohesive file because it passed
a number costs a reader the jump and buys nothing.

### Visibility

Visibility is the architecture, so it is decided rather than reached for.

`pub` is a promise on a published crate. `pub(crate)` is deliberate and each one
should have an answer to why the whole crate may see it; `Cell::from_parts` is
`pub(crate)`, so outside the crate a cell comes only through it, whether parsed
from a bag of cells or built by the `Builder`; that single choice is what the
cell model's guarantee rests on. There are 18
`pub(crate)` and no `pub(super)` in the workspace today, and that is the baseline
worth keeping.

A `pub(crate)` that exists so a sibling module can reach an item is a defect in
the split rather than a requirement, and the fix is to make the sibling a child.

I/O belongs in one file per crate, behind a trait. In `ton-net-adnl` the
`Transport` trait and its TCP implementation are in `transport.rs`, and
`frame.rs`, `handshake.rs` and `connection.rs` between them reference tokio zero
times. Keeping that at zero is what leaves room for a browser transport without
touching a line of protocol.

### Tests

An integration test binary covers a public boundary, and the topics under it are
modules of that one binary. The form is `tests/<boundary>/main.rs` with the topics
beside it. A bare `tests/<boundary>.rs` is a crate root, so its `mod` declarations
resolve next to it rather than beneath it, and the directory form is what gives
one target instead of several.

The count is what costs. Cargo builds every `.rs` directly under `tests/` as its
own crate, links the library into each, and runs them one after another.

This workspace has one test binary per 685 lines of source. libsignal has one per
5,838 and rust-analyzer one per 35,940. Tests that need a crate's internals stay
inside `src/` under `#[cfg(test)]`, as the cell crate's properties already do.

### Bindings

The binding surface is declared once and converted per target. Domain types are
not mirrored per language.

libsignal is the worked example: one shared crate declares each bridged function
against the domain, a `convert.rs` per target holds the type conversions, and the
per-language crates come to 2, 8 and 421 lines. The alternative is what this
repository has one instance of and would have six: `bindings/node` mirrors eleven
core types with their conversions, and each copy is somewhere a field can drift
in silence.

This shape has to exist before the second binding, because after the fourth it is
no longer a refactor.

### Naming

No module is named for its role. `utils`, `common`, `helpers` and `misc` cannot
carry an invariant, so nothing can be said about them and everything ends up
depending on them. There are none today.

## Alternatives considered

- **A maximum file length.** Rejected on the measurement. Files over 1000 lines
  are 16% of rust-analyzer, 14% of matrix-rust-sdk and 7% of libsignal; this
  repository has none at all, and its largest file sits below rust-analyzer's
  90th percentile. A limit would invent a constraint none of the comparisons hold, and
  the splits it forced would be the sideways kind that widen visibility.
- **`foo/mod.rs` for module directories.** Rejected, though it is a real choice
  rather than a mistake: matrix-rust-sdk uses it throughout, with 122 of them.
- **Grouping crates under a directory**, as architecture.md describes with
  `core/`. Rejected because the crate would no longer be named for the directory
  it sits in, and because the grouping is what rots first.
- **A mechanical check for any of this.** Rejected. Every rule here turns on
  intent: whether a crate is a layer, whether a `pub(crate)` serves a sibling,
  whether two vocabularies are in one file. A checker sees shape and would pass
  the sideways split and fail the cohesive file.

## Consequences

- The module tree starts where a file next earns one, rather than in a sweep.
  `dict.rs` is the largest at 987 lines, so it is the likely first.
- architecture.md's repository shape is corrected to the flat layout that exists,
  and the TVM, the DHT and the remaining bindings are placed under it.
- The test binary count is the largest measured gap and closing it is separate
  work, since consolidating changes no behaviour and touches every crate.
- `ton-net-adnl` and `ton-net-lite` are not built for wasm32 in CI, which only
  covers `ton-net-tl`, `ton-net-cell` and `ton-net-block`. The browser target
  NET-ADR-001 describes needs that gap closed, and the `Transport` seam is where
  it closes.
- NET-ADR-001 describes the core as sans-I/O. That is true of the protocol
  modules and not of the crates, which depend on tokio unconditionally. The rule
  above states the property that actually holds.
