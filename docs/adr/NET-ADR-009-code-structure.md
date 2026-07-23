---
id: NET-ADR-009
title: Flat layered crates, and how a crate grows
status: accepted
date: 2026-07-23
supersedes: none
superseded-by: none
---

# NET-ADR-009: Flat layered crates, and how a crate grows

## Context

NET-ADR-002 fixes the architecture: the protocol and all of the verification are one audited
Rust core, written once as a set of workspace crates, behind a sans-I/O seam and thin
bindings. It states that the core crates form a flat layered set with the TL codec and the
cell model at the base and the facade on top, and it leaves the full structure and how a
crate grows to this record.

Two organizational questions follow, and this record settles both. The first is how the
crates sit relative to each other and to the workspace. The second is how a single crate is
structured on the inside as it grows.

Three forces shape the answer. The code is adversarial: a decoder reads bytes from a server
the client does not trust, so a reviewer has to be able to find a decoder and read it whole,
and a bound the read path enforces has to be the same bound the write path and a view over
the same bytes enforce. The performance bar rules out organization that costs anything at
runtime. And consumer priority means the breadth an indexer or a node tool needs is carried
as isolated paths that a lighter consumer does not compile (NET-ADR-001).

## Decision

1. **Flat crates, each named for its directory.** The workspace crates sit directly under
   `crates/`, one directory each, no nesting. A crate's package name is its directory name:
   `crates/ton-net-cell` is the crate `ton-net-cell`. The six core crates are `ton-net-tl`,
   `ton-net-cell`, `ton-net-block`, `ton-net-adnl`, `ton-net-lite`, and the `ton-net` facade.
   The name states the layer, and the directory is found from the name without a map.

2. **A virtual workspace manifest beside them.** The root `Cargo.toml` is a virtual manifest:
   it declares `[workspace]` and carries no `[package]` of its own. `members` lists the six
   core crates and the Node binding; `default-members` lists the six core crates, so a bare
   build does not compile the binding; the feasibility spike is excluded. `[workspace.package]`
   holds the one version, edition, license, and repository every crate inherits, and
   `[workspace.dependencies]` holds one line per dependency, internal crates by path and
   version and external crates on the vetted lines NET-ADR-004 fixes. Each crate opts in with
   `.workspace = true`, so a version or a lint set is one edit for the whole workspace.

3. **One-way dependency layering.** The internal dependencies form a directed acyclic graph
   that points one way, from the facade down to the foundations, and never back.
   `ton-net-tl`, the TL codec, and `ton-net-cell`, the cell model and bag-of-cells codec, sit
   at the base and depend on no other workspace crate. `ton-net-block` builds on `ton-net-cell`
   and `ton-net-tl`; `ton-net-adnl` builds on `ton-net-tl`; `ton-net-lite` builds on
   `ton-net-adnl` and `ton-net-tl`; and `ton-net`, the facade, builds on `ton-net-lite`,
   `ton-net-adnl`, `ton-net-block`, and `ton-net-cell` and is the only crate a consumer or a
   binding depends on (NET-ADR-002). A lower layer never names a higher one, so a consumer
   takes a base crate without pulling the layers above it.

4. **Inside a crate, structure follows visibility, not file length.** A module is a single
   file until a child earns a place. When a part of it becomes a specialization worth reading
   on its own, that part moves down into a directory that sits beside the file and takes the
   file's name: the file stays as the trunk, and the directory holds the children. The trigger
   is a child that has earned separation, never a line count. In `ton-net-cell` the cell model
   grew this way: `cell.rs` beside `cell/`, `dict.rs` beside `dict/`, `boc.rs` beside `boc/`,
   and likewise `builder`, `slice`, `merkle`, and `usage`. `error.rs` and the in-crate
   property tests stay single files, because nothing inside them earned a directory.

5. **`pub(super)` is the currency a child exposes to its parent.** A child publishes upward to
   its trunk exactly the specialized function or type the trunk composes, and marks it
   `pub(super)` so it reaches the trunk and stops there. The trunk then re-exports outward,
   with `pub use`, only the part of that the crate's public surface needs. In `boc/`,
   `header.rs` exposes `read_header` and `parse.rs` exposes `read_and_build`, `verify_roots`,
   and `build_cell`, each `pub(super)`, and the `boc.rs` trunk names them to compose the read
   path; in `cell/`, `level.rs` exposes the level-mask helpers `level_of`, `hash_index`,
   `bits_descriptor`, and `refs_descriptor` the same way. At the crate root, `lib.rs` declares
   every module private with a plain `mod` and re-exports the public surface with `pub use`, so
   the surface of the crate is one list in one file.

6. **The shared model of a trunk stays in the trunk.** When a trunk grows children, the model
   they share does not move down with them; it stays in the trunk where each child reaches it
   through the parent. `boc.rs` is the worked example: the read path is `parse`, the write path
   is `serialize`, and a `view` reads a bag without building it, and the parts all three share,
   the magic bytes, the cell and depth bounds, the checksum, the bounded byte reader, and the
   `Header` those reads fill, stay in `boc.rs`. The read path, the write path, and the view
   reach one header and one reader, so a bound is defined once and cannot hold in one path and
   lapse in another. `cell.rs` keeps the immutable `Cell` value and its accessors in the trunk
   while `exotic`, `level`, and `hash` take the kind, the level arithmetic, and the hashing;
   `dict.rs` keeps `Lookup` and the descent written once over a private shape seam in the
   trunk while `plain`, `aug`, and `prefix` are the shapes and `label` is the codec.

7. **Node-scale breadth sits as isolated children.** In `boc/`, past the `header`, `parse`,
   `serialize`, and `view` a lighter consumer takes and the optional `compress` child behind a
   feature, the node-scale children carry the paths an indexer or node tool needs: `large.rs`
   writes a bag as a stream of chunks without holding the whole of it, `lazy.rs` builds a cell
   on demand and keeps what it builds, and `random.rs` verifies or reads a bag larger than its
   materialized graph would fit. They are separate files reached through the trunk, and the
   default read-and-build path a wallet takes does not compile or run them. This is the
   consumer-priority guard of NET-ADR-001 realized in the layout: breadth carried as isolated
   paths that cost a lighter consumer nothing.

## Alternatives considered

- **One crate for the whole client.** Rejected. A single library has no enforced layering, so
  the audit target is one undivided blob and a consumer that wants only the cell model pulls
  the transport and the network with it. The flat layered crates give the reviewer a bounded
  target and the consumer a base crate it can take alone.
- **Nested crate paths grouping crates by role**, for example a transport directory holding
  the ADNL and liteserver crates. Rejected. The extra directory level carries no dependency
  meaning, and it breaks the rule that a crate's directory is its name. Flat and
  name-equals-directory keeps the crate graph legible and every package findable by its name.
- **Split a file once it passes a line threshold.** Rejected. A length trigger cuts a cohesive
  model across files that then have to re-export each other's internals to be whole again. The
  visibility trigger cuts only where a child is genuinely separable, and it keeps the shared
  model in one trunk rather than scattering it to satisfy a line count.
- **A shared `common` or `util` crate or module for cross-cutting types.** Rejected. The model
  a subsystem shares belongs in that subsystem's trunk, reached by its own children through
  `pub(super)`. A common bucket pulls unrelated code together, and a base crate depending on it
  would point an edge the wrong way through the layering.
- **Make a child's internals visible crate-wide with `pub(crate)`.** Rejected as the default.
  `pub(super)` keeps a specialization visible to exactly the trunk that composes it, so the
  boundary the directory drew stays real; crate-wide visibility erases it and lets a
  specialized helper be reached from anywhere in the crate. `pub(crate)` is used only where a
  helper genuinely serves more than its trunk, such as an in-crate property test reaching a
  parser internal the public API cannot construct.

## Consequences

- The audit target is legible. A decoder is one trunk plus its children, found from its name,
  and the crate graph shows the layering at a glance.
- A consumer takes only the layer it needs. A wallet depends on `ton-net-cell` without the
  network; a binding depends on `ton-net` alone (NET-ADR-002).
- Growth is local. A new specialization is a new child file that exposes `pub(super)` upward.
  It does not change the trunk's public surface or the crate graph.
- A shared bound is enforced once. Because the read path, the write path, and the view over a
  bag reach one header and one reader in the trunk, a check cannot be present in one path and
  missing in another.
- The layout carries no runtime cost, and the node-scale and optional paths are separate files
  or feature-gated modules a lighter build does not compile, so the performance bar and the
  binary size a mobile consumer counts are unaffected (NET-ADR-001).
- The virtual manifest keeps one version, one lint set, and one line per dependency across the
  workspace, so a bump or a lint change is a single edit.

## Chain scope

The organization rule is general in form and is not TON-specific. What it organizes is the
TON core NET-ADR-002 fixes: the crates decode TON structures and speak the TON client
protocol. Composing several chains lives above ton-net, in the consumer (NET-ADR-001).

## Custody and security

No user keys today (NET-ADR-002). The layout's contribution to safety is that the shared model
of an adversarial subsystem stays in one trunk, so the bounds a decoder checks, the cell and
depth limits, the checksum, the reader that refuses to read past its end, are defined once and
reached by the read path, the write path, and a view alike, and cannot be enforced unevenly
across them. `pub(super)` keeps a child's internals inside the trunk that guards them, so a
specialized helper that is safe only behind the trunk's checks cannot be reached around them
from elsewhere in the crate. The crate root carries the safety posture for every child at
once: `ton-net-cell`'s `lib.rs` sets `forbid(unsafe_code)` and denies the panic and
indexing lints a decoder must not trip, and those apply to every module in the tree beneath
it. This record fixes the code shape and does not change the custody position.

## Verification

- The flat-name rule is checkable. Every workspace member is a directory under `crates/` whose
  package name equals its directory name.
- The one-way layering is observable in the manifests. The internal dependencies of the six
  crates form a directed acyclic graph with `ton-net-tl` and `ton-net-cell` at the base,
  depending on no other workspace crate, and `ton-net` at the top; no crate depends back up
  its layer.
- The trunk-holds-the-model rule is observable. `boc.rs` defines the magic, the bounds, the
  checksum, the reader, and the `Header`, and `boc/parse.rs`, `boc/serialize.rs`, and
  `boc/view.rs` reach them through the parent rather than each holding a copy.
- The visibility currency is observable. A child exposes its specialization upward with
  `pub(super)`, the trunk re-exports outward with `pub use`, and the crate root declares every
  module private and names the public surface in one place.
