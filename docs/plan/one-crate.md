---
title: ton-net as one library crate
status: draft
date: 2026-08-16
---

# One library crate

**The six library crates become one, `ton-net`, in a single pull request. The binding stays a crate of its own.**

Every claim about this tree carries a `file:line` anchor or a count that was counted. Anchors were taken at `6bddcd3`.

---

## 1. Why the current split is not what it looks like

The six crates read as six layers. They are not six of anything. Measured over `crates/*/src/**/*.rs`:

| crate | lines | files | share |
|---|---:|---:|---:|
| `ton-net-cell` | 16,303 | 41 | **70.6%** |
| `ton-net` | 2,391 | 9 | 10.4% |
| `ton-net-block` | 2,228 | 10 | 9.7% |
| `ton-net-adnl` | 1,002 | 5 | 4.3% |
| `ton-net-tl` | 612 | 4 | 2.7% |
| `ton-net-lite` | 541 | 3 | 2.3% |
| **total** | **23,077** | **72** | |

One crate is 70.6% of the library. Two of the remaining five are under 620 lines in four files or fewer. `ton-net-lite` is 541 lines: a request builder, a response decoder, and a wrapper type. That is a module. It carries a manifest, a version, a changelog entry, a published artifact on a registry, a row in the license notices, and a line in four documents, and it is 2.3% of the code.

The cost of that is not theoretical. It is what refused a single pure function this month: adding one is not adding a file, it is adding a published artifact, and the count `six` is written into `docs/adr/NET-ADR-008-versioning-and-bindings.md`, `docs/adr/NET-ADR-009-code-structure.md`, `docs/release-process.md` and `scripts/check-versions.mjs`.

## 2. The property the split was supposed to carry, and what it actually carries

`NET-ADR-011:189-193` states the mechanism plainly, and the write-path plan leaned on it:

> "the enforcement is the absent dependency edge rather than anyone's diligence"

The claim built on it was that `ton-net-block`, the crate that decides whether a validator signature is good, **has no socket, no clock, and no randomness source**, because its manifest declares no `tokio`, no `getrandom`, no `ton-net-adnl` and no `ton-net-lite`.

**That claim is false, and the compiler says so.** Appending this to `crates/ton-net-block/src/lib.rs` and running `cargo build -p ton-net-block` finishes clean, with no manifest change:

```rust
fn reachable_today() -> std::io::Result<std::net::TcpStream> {
    let now = std::time::SystemTime::now();
    let _ = now;
    std::net::TcpStream::connect("127.0.0.1:1")
}
```

The absent dependency edge excludes an async runtime and a dependency-provided entropy source. It has never excluded `std::net`, `std::time`, `std::fs` or `std::process`, because `std` needs no edge. The sentence should have been "no async runtime and no dependency-provided randomness", and it was written a scope wider than the thing under it.

The property is nonetheless real in the code as written. Counting over the three sans-I/O crates:

| crate | `std::net` / `fs` / `process` / `env` / `SystemTime` / `Instant` hits |
|---|---:|
| `ton-net-tl` | 0 |
| `ton-net-block` | 0 |
| `ton-net-cell` | 0 |

`ton-net-cell` carries eleven `std::thread` references, all in `boc/parse.rs` and all under the `parallel` feature, which is the threaded parse and is meant to be there.

So the discipline holds today by nobody having broken it, not by anything refusing to compile. **A merge therefore surrenders no enforcement, because there is none to surrender.**

## 3. What replaces it, and it is stronger

A module-import check over the source text, in the shape `scripts/check-default-deps.mjs` and `scripts/check-unsafe-posture.mjs` already use, with the same two-reading discipline: assert the absence, and assert the same reading finds a present edge, so a matcher that matches nothing cannot pass for free.

`scripts/check-layers.mjs` refuses, inside `src/{cell,tlb,proof,tl,wallet}/`:

- `use crate::{adnl, lite, client, sync, send}`
- `tokio`, `getrandom`
- `std::net`, `std::fs`, `std::process`, `std::env`, `std::time::SystemTime`, `std::time::Instant`

and inside `src/lite/`:

- `use crate::cell`

and asserts, in the same reading, that `src/tlb/` does reach `crate::cell` and `src/proof/` does reach both, so a matcher that finds nothing cannot pass for free.

This catches the four `std` reaches the crate graph never could. **It is strictly stronger than the current arrangement on the property that matters, and it is work that has to be done in either structure**, since the survey established that adding `tokio.workspace = true` to `ton-net-block` today passes every check in `just gate` in silence.

`std::thread` stays permitted inside `src/cell/boc/`, because the threaded parse is a deliberate capability with its own feature. That exception is named in the check rather than left as a hole in the pattern.

## 4. The module tree

The shape is taken from a widely deployed client in the surveyed corpus, which is one module with flat top-level packages and has been through exactly this growth. Its package sizes are worth stating, because they show the same lopsidedness this tree has and show that it was not treated as a reason to split the artifact:

| its package | lines | the same thing here |
|---|---:|---|
| `<vm>/cell` | 20,392 | `ton-net-cell`, 16,303 |
| `<tlb>` | 11,265 | `ton-net-block`, 2,228, not yet grown |
| `<client>` | 4,549 | `ton-net`, 2,391 |
| `<client>/wallet` | 4,279 | not built |
| `<adnl>` | 3,929 | `ton-net-adnl`, 1,002 |
| `<liteclient>` | 2,262 | `ton-net-lite`, 541 |
| `<tl>` | 2,159 | `ton-net-tl`, 612 |
| `<crc16>` | 32 | part of `codec.rs` |

One module, and a 32-line package sits at the top of it beside a 20,392-line one. In that language a package is a namespace and the module is the published artifact, which is the same relation a Rust module has to a crate. **This tree currently publishes what that one namespaces.**

Adopting the shape:

```
crates/ton-net/
  Cargo.toml
  src/
    lib.rs                  the facade: re-exports, VERIFY_EPOCH, the crate docs

    cell/                   the cell engine, one tree, unchanged internally
      boc.rs  boc/          compress, header, large, lazy, parse, random, serialize, view
      builder.rs builder/   address, snake
      cell.rs cell/         dump, exotic, hash, json, level, payload, refs
      dict.rs dict/         aug, floor, label, plain, prefix, typed
      merkle.rs merkle/     proof, update, virtualize
      slice.rs slice/       address, compare, snake
      usage.rs usage/       trace
      codec.rs  error.rs  proptests.rs

    tlb/                    TON's typed structures
      account.rs block.rs coins.rs shard.rs
      message/              W3
      error.rs

    proof/                  the verification engine, which is what this library is for
      chain.rs validators.rs signature.rs account.rs

    tl/                     adnl.rs lite.rs signed.rs
    adnl/                   connection, frame, handshake, transport      [feature: net]
    lite/                   client, types                                [feature: net]

    wallet/                 families, and what a family needs            W4
      v4r2.rs seed.rs address.rs

    address.rs  codec.rs  config.rs  error.rs  proof.rs  verified.rs
    client.rs  sync.rs  send.rs                                          [feature: net]

crates/ton-net-node/        unchanged, still its own crate
```

### Two places this departs from the shape it follows, and why

**The cell engine stays one nested tree rather than being promoted to the crate root.** An earlier draft of this plan promoted its ten modules to the root, on the reasoning that they are 70.6% of the library. That was wrong: it scatters `boc/`, `dict/`, `merkle/` and `slice/` across the same level as `client.rs` and `config.rs`, mixing an engine with a facade. The reference keeps its equivalent as one package and that is the better call. It also dissolves both of the naming collisions section 6 was written to resolve.

**The verification engine gets its own top-level module, which the reference does not do.** There the proof code is split between the cell package and the client package. Here it is `proof/`, holding `chain`, `validators`, `signature` and the account check, because verifying every answer rather than trusting the server is what this library is for and it should be one named thing a reader can find. `ton-net-block` today mixes it with the typed structures; `tlb/` and `proof/` separate them.

### One placement question the shape answers outright

Seed-phrase handling sits **inside the wallet package** in the reference, beside the families that consume what it derives, not in a crypto package and not in a module of its own. So: `src/wallet/seed.rs`. TON Connect proof verification sits there too, for the same reason.

That is where a month of argument about a seventh crate lands: **it is a file next to the wallet.**

## 5. Features, and the wasm build gets better

```toml
[features]
default  = ["net"]
net      = ["dep:tokio"]
compress = ["dep:lz4_flex"]
json     = ["dep:serde_json"]
parallel = []
```

`just wasm` today builds three crates and stops: `cargo build --target wasm32-unknown-unknown -p ton-net-tl -p ton-net-cell -p ton-net-block` (`justfile:74`). A wasm consumer therefore cannot reach `Verified`, address parsing, or the offline proof check, because all three live in the facade.

After the merge it is `cargo build --target wasm32-unknown-unknown --no-default-features`, and that build carries `Verified`, `address`, and `proof` as well, because none of them touches a socket. **The browser target gains three capabilities it does not have today**, and it gains them from the merge rather than from new work.

## 6. The collisions dissolve, but one of them was a real finding

Seven basenames appear twice across the six `src` trees: `address.rs`, `client.rs`, `codec.rs`, `error.rs`, `lib.rs`, `proof.rs`, `snake.rs`. Under the tree of section 4 every one of them lands under a different parent, so none collides: `cell/codec.rs` beside `codec.rs`, `cell/error.rs` beside `tlb/error.rs` beside `error.rs`, `lite/client.rs` beside `client.rs`, `proof/` beside `proof.rs`.

**One of them was a finding rather than a collision, and it survives the reshuffle.** Both files implement base64:

- `crates/ton-net-cell/src/codec.rs`: "Base64 and hex: the two spellings a bag of cells and a cell hash travel in."
- `crates/ton-net/src/codec.rs`: "Small self-contained encoders: base64 and CRC16 ... written here rather than pulled as dependencies."

Two base64 implementations, in one library, invisible to each other because a crate boundary sat between them. They merge into one, and the merge is gated on a differential: the two must agree byte for byte over the same inputs before either is deleted, since one may be standard alphabet and the other url-safe. **If they disagree, that is a bug this migration found, and it is reported rather than papered over.**

## 7. The five published names

`ton-net-tl`, `ton-net-cell`, `ton-net-adnl`, `ton-net-lite` and `ton-net-block` are published on crates.io at 0.4.2. They are not yanked: yanking breaks anyone who pinned one, and a pre-1.0 library that yanks is not one anybody should depend on.

Each gets one final release whose `lib.rs` is a deprecation notice and nothing else, pointing at the module inside `ton-net` that replaced it. After that they stop moving. `docs/release-process.md` records that the five are frozen and why.

## 8. The migration, as one pull request

Ordered so the tree compiles at as many points as it can, and so history survives.

1. `git mv` each crate's `src` tree into `crates/ton-net/src/` at its new path, one commit per source crate, no content edits. History follows the file. `ton-net-block` splits across two destinations here, `tlb/` and `proof/`, which is the one move that is not a straight rename.
2. Convert each moved `lib.rs` into the module's `mod.rs`, or dissolve it into the parent where it only re-exported.
3. Rewrite paths: `ton_net_cell::X` becomes `crate::X`, and so on for the other four. This is the largest mechanical step and it is the one to review by count rather than by eye.
4. Drop cross-crate `pub` to `pub(crate)` or `pub(super)` wherever the item has no external user, per `NET-ADR-009:67-69`, which already names `pub(super)` as the currency a child exposes to its parent.
5. Merge the two `codec.rs` behind the differential of section 6.
6. Reparent `error.rs` into `src/error/`.
7. Feature-gate `adnl/`, `lite/`, `client.rs`, `sync.rs` and `send.rs` behind `net`. `verified.rs`, `address.rs`, `proof.rs` and `config.rs` stay ungated, which is what gives the browser target the three capabilities section 5 names.
8. Merge `tests/` trees, renaming any colliding target, and merge `benches/`.
9. One `Cargo.toml`; workspace `members` drops to two entries.
10. `deny.toml`, `about.hbs`, the notices, and the release workflow.
11. `scripts/check-versions.mjs`, `docs/release-process.md`, `docs/architecture.md`, `docs/api-design.md`, `docs/design/system-design.md`, `NET-ADR-008`, `NET-ADR-009`.
12. `scripts/check-layers.mjs` and its `just gate` entry, per section 3.
13. The five deprecation releases, per section 7.

## 9. The floor: what proves the move changed nothing

The whole risk of this migration is a semantic change smuggled in under a mechanical one. Three things bound it, and all three are commands.

**`cargo test -p ton-net --test epoch`, unedited.** `crates/ton-net/tests/epoch.rs` pins the accept and reject boundary of the public verifier as a transcript. If the migration alters what the verifier accepts, that test is what says so. Its first line is the verification epoch, which stays 2, per `NET-ADR-008:56-60`: this migration accepts no new kind of proof and changes no acceptance condition.

**Every existing test passes with only its import paths changed.** Not rewritten, not relaxed, not deleted. A test that has to be edited to pass is the migration changing behaviour, and each one is reported rather than adjusted.

**The fixture hashes do not move.** `crates/*/tests/fixtures/` holds captured mainnet bags whose parses are asserted as exact equalities. They are the same bytes before and after.

Plus the standing floor: `just gate` green, and `just wasm` replaced by the `--no-default-features` build of section 5.

## 10. What this does not do

- It does not merge the binding. `crates/ton-net-node` stays its own crate, with its own MSRV of 1.88 against the library's 1.85 (`justfile:165-166`).
- It does not change any public type, function signature, or wire behaviour. A consumer's `use ton_net::X` keeps working; a consumer's `use ton_net_cell::X` does not, which is why the five get a deprecation release rather than silence.
- It does not raise the verification epoch.
- It does not settle where seed-phrase import lands. That is the v0.5.0 plan's, and this migration is what makes it a placement question rather than a publishing one.

## 11. The cost that is real, and not talked out of

**Incremental compile time.** Six crates compile in parallel and cache independently; one crate is one compilation unit, so an edit anywhere in 23,077 lines recompiles all of it. The workspace already shares one `target/`, so nothing else changes, but this is a genuine loss and it grows with the crate. It is accepted because the alternative has been paid in a different currency: a published artifact per module, and a design question turned into a release question.

**One docs.rs page for 23,077 lines.** Module docs carry more weight after this, not less.

**Two accepted records stop being true** and are edited in this change rather than in a record of their own, the same way the signer-seam wording was.
