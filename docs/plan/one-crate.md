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

`ton-net-cell` carries eleven `std::thread` references, all in `boc/parse.rs`. **Eight are under the `parallel` feature. Three are not**, and the reason is worth writing down because it is the same class of error this section is about. `parse.rs:349` guards with `cfg!(feature = "parallel")`, the macro rather than the `#[cfg]` attribute, so the body compiles in every configuration and `std::thread::available_parallelism()` at `:351` is in the default build. `parse.rs:1523,1525` sit in a `#[test]` at `:1499` that carries no feature attribute at all.

**And randomness arrives the same way, unnoticed.** `ton-net-cell` declares no `getrandom` and reaches OS randomness anyway, nineteen times, through `HashMap` and `HashSet`: `std`'s default hasher seeds `RandomState` from the OS on first use. The sites are `cell.rs:420-421`, `boc/serialize.rs:6,41,79`, `usage.rs:18,51,65,133,173` and eight in `merkle/update.rs`. Nothing in `just gate` reads for it, and the wasm build would not catch it either, since `std::net`, `std::fs` and `SystemTime` all compile for `wasm32-unknown-unknown` and fail only at runtime.

So the discipline holds today by nobody having broken it, not by anything refusing to compile. **A merge therefore surrenders no enforcement, because there is none to surrender.**

## 3. What replaces it, and it is stronger

A module-import check over the source text, in the shape `scripts/check-default-deps.mjs` and `scripts/check-unsafe-posture.mjs` already use, with the same two-reading discipline: assert the absence, and assert the same reading finds a present edge, so a matcher that matches nothing cannot pass for free.

`scripts/check-layers.mjs` refuses, inside `core/src/{cell,tlb,proof,tl}/` and `core/src/client/wallet/`:

- `use crate::{adnl, lite, client}`
- `tokio`, `getrandom`
- `std::net`, `std::fs`, `std::process`, `std::env`, `std::time::SystemTime`, `std::time::Instant`

and inside `core/src/lite/`:

- `use crate::cell`

and asserts, in the same reading, that `core/src/tlb/` does reach `crate::cell` and `core/src/proof/` does reach both, so a matcher that finds nothing cannot pass for free.

The refused set is three module names rather than five because `sync` and `send` moved under `client` in section 4, so refusing `crate::client` refuses them with it. The wallet is guarded even though it lives inside `client/`, because building an external message needs no socket and is the one thing in that package that must stay reachable from the browser build.

This catches the four `std` reaches the crate graph never could. **It is strictly stronger than the current arrangement on the property that matters, and it is work that has to be done in either structure**, since the survey established that adding `tokio.workspace = true` to `ton-net-block` today passes every check in `just gate` in silence.

`std::thread` stays permitted inside `core/src/cell/boc/`, because the threaded parse is a deliberate capability with its own feature. That exception is named in the check rather than left as a hole in the pattern, and the three ungated references section 2 found are fixed rather than exempted.

**What the check deliberately does not flag: `HashMap` and `HashSet`.** They are how randomness actually arrives in the cell engine today, and flagging nineteen legitimate uses to catch a property nobody is attacking would be noise that gets turned off within a release. The reach is stated in section 2 rather than checked, and that gap is named rather than closed.

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
core/
  Cargo.toml              name = "ton-net", which is still the published name
  src/
    lib.rs                the crate docs, the re-exports, VERIFY_EPOCH

    cell.rs  cell/        the cell engine, one tree, unchanged internally
      boc.rs  boc/          compress, header, large, lazy, parse, random, serialize, view
      builder.rs builder/   address, snake
      cell.rs cell/         dump, exotic, hash, json, level, payload, refs
      dict.rs dict/         aug, floor, label, plain, prefix, typed
      merkle.rs merkle/     proof, update, virtualize
      slice.rs slice/       address, compare, snake
      usage.rs usage/       trace
      codec.rs  error.rs  proptests.rs

    tlb.rs  tlb/          TON's typed structures
      account.rs  block.rs  coins.rs  shard.rs
      message.rs message/                                        W3
      error.rs

    proof.rs  proof/      the verification engine, which is what this library is for
      chain.rs  validators.rs  signature.rs

    tl.rs  tl/            adnl.rs  lite.rs  signed.rs

    adnl.rs  adnl/        connection, frame, handshake, transport     [feature: net]
    lite.rs  lite/        client, types                               [feature: net]

    client.rs  client/    the facade
      sync.rs  send.rs                                               [feature: net]
      proof.rs              the standalone check, at the facade's error type
      wallet.rs wallet/     v4r2, seed, address                       W4

    address.rs  codec.rs  config.rs  error.rs  verified.rs

bindings/node/            unchanged, still its own crate
```

`crates/` goes away with the last thing in it. A directory named for a plurality, holding one, says something about the project that has stopped being true.

### The facade is a package, not a scatter, and an earlier draft got that wrong

That draft put `client.rs`, `sync.rs`, `send.rs`, `proof.rs` and the wallet at the crate root as loose files. It is worth saying why that is wrong, because the reason is not taste.

**The language refuses it.** `src/proof.rs` and `src/proof/` are not two modules in Rust, they are one: the file is the module's body and the directory holds its children. So a root `proof.rs` carrying the facade's fifty-two-line check and a root `proof/` carrying the three-hundred-line engine are the same name twice, and no re-export resolves that. Section 6 counted `proof.rs` among the basenames that dissolve under different parents. Under the flattened tree it did not dissolve, and the tree hid it.

Grouping the facade under `client/` is also the closer adoption, not the looser one: the shape being followed has one client package, and its own table above puts 4,549 lines in it. So `client/proof.rs` beside `proof/`, and the collision is gone because the parents are genuinely different rather than drawn that way.

### Two places this departs from the shape it follows, and why

**The cell engine stays one nested tree rather than being promoted to the crate root.** An earlier draft promoted its ten modules to the root, on the reasoning that they are 70.6% of the library. That was wrong: it scatters `boc/`, `dict/`, `merkle/` and `slice/` across the same level as `client.rs` and `config.rs`, mixing an engine with a facade. The reference keeps its equivalent as one package and that is the better call.

It costs one stutter. `src/cell/cell.rs` is real, so `ton_net_cell::cell::Cell` becomes `crate::cell::cell::Cell` internally. A reader never types it, because `lib.rs` re-exports `Cell` at the root and always has, but the internal paths carry it and renaming a module to avoid it would be a cosmetic edit inside the largest tree in the library.

**The verification engine gets its own top-level module, which the reference does not do.** There the proof code is split between the cell package and the client package. Here it is `proof/`, holding `chain`, `validators` and `signature` beside the engine body, because verifying every answer rather than trusting the server is what this library is for and it should be one named thing a reader can find. `ton-net-block` today mixes it with the typed structures; `tlb/` and `proof/` separate them.

**`account.rs` goes to `tlb/`, once.** An earlier draft listed it under both, which cannot be: there is one `crates/ton-net-block/src/account.rs` and it is a decoder, `Account`, `AccountStatus`, `skip_address`, `load_status`. The account *check* is not a file at all, it is `verify_account` inside `crates/ton-net-block/src/proof.rs:255`, and it travels with the engine body.

### One placement question the shape answers outright

Seed-phrase handling sits **inside the wallet package** in the reference, beside the families that consume what it derives, not in a crypto package and not in a module of its own. So: `core/src/client/wallet/seed.rs`. TON Connect proof verification sits there too, for the same reason.

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

`just wasm` today builds three crates and stops: `cargo build --target wasm32-unknown-unknown -p ton-net-tl -p ton-net-cell -p ton-net-block` (`justfile:81-82`, mirrored at `.github/workflows/ci.yml:221-222`). A wasm consumer therefore cannot reach `Verified`, address parsing, or the offline proof check, because all three live in the facade.

After the merge it is `cargo build --target wasm32-unknown-unknown --no-default-features`, and that build carries `Verified`, `address`, `config`, `proof`, and the ADNL handshake and frame crypto as well, because none of them touches a socket. **The browser target gains capability it does not have today**, and it gains it from the merge rather than from new work.

Two corrections to what gets gated, both from reading the sources rather than from the module names:

- **`client/sync.rs` does not need the gate.** It names `std::time::Duration` once, as a parameter type at `crates/ton-net/src/sync.rs:235`, and never reads a clock. `Duration` is arithmetic and builds for this target.
- **`adnl/transport.rs` cannot be gated whole.** It holds `TcpTransport`, which is a socket, and the `Transport` trait and `TransportError`, which are pure and which `lite/client.rs` needs. The trait moves to its own file so the socket can be gated without taking the trait with it. That split is a migration step, not a follow-up.

## 6. The collisions dissolve, but one of them was a real finding

Seven basenames appear twice across the six `src` trees: `address.rs`, `client.rs`, `codec.rs`, `error.rs`, `lib.rs`, `proof.rs`, `snake.rs`. Five land under a different parent and cost nothing: `cell/codec.rs` beside `codec.rs`, `cell/error.rs` beside `tlb/error.rs` beside `error.rs`, `lite/client.rs` beside `client.rs`, `cell/builder/snake.rs` beside `cell/slice/snake.rs`, four `address.rs` under four parents. `lib.rs` is not a collision at all: one survives as the crate root and the other five dissolve into the module bodies they became.

**Two of the seven cost something, and an earlier draft of this plan got both wrong.**

**`proof.rs` was counted as free and is not.** Section 4 carries the correction: a root `proof.rs` and a root `proof/` are one module in this language, not two, so the facade's check and the engine collided under the flattened tree the draft drew. The facade moves into `client/` and the parents become genuinely different. Two functions named `verify_account` survive that move, at `proof::verify_account` returning `BlockError` and `client::proof::verify_account` returning `Error`, and they survive because two error types survive. That is an adapter, not a duplicate, and it is one line.

**The other is two base64 decoders in one library.** That draft said to merge them behind a differential, and to treat disagreement as a bug the migration found. They disagree, and it is not a bug: each rule is deliberate and each has a test pinning it.

- `crates/ton-net-cell/src/codec.rs:37` **refuses** the URL-safe alphabet, pinned by `base64_refuses_the_url_safe_alphabet` at `:362`. A bag of cells and a cell hash travel in standard base64, and accepting a second spelling of the same bytes would give one bag two encodings.
- `crates/ton-net/src/codec.rs:14-16` **accepts both**, pinned by `base64_decodes_the_url_safe_alphabet` at `:157` and `both_alphabets_spell_one_value` at `:176`. It serves config keys, which are standard, and user-friendly addresses, which are URL-safe.

Two domains, two acceptance rules, both correct. Merging them into one function breaks one test set and would silently widen what the cell decoder accepts, which is the opposite of what this library is for.

**Resolution: two named decoders, each staying where its domain is.** The strict one is a cell concern and stays in `cell/codec.rs`; the permissive one serves config keys and friendly addresses, which are not cell concerns, and stays at `codec.rs`. They already sit under different parents in section 4's tree, so the basename never collided, and each keeps its own tests and gains a doc sentence naming the domain it serves. The duplication that looked large is small: the facade's side is decode only, it has no encoder, and `crates/ton-net/src/codec.rs:9-10` already records that hex is not duplicated because it calls the cell crate's. **One function was duplicated, not a module.**

## 7. The five published names

`ton-net-tl`, `ton-net-cell`, `ton-net-adnl`, `ton-net-lite` and `ton-net-block` are published on crates.io at 0.4.2. They are not yanked: yanking breaks anyone who pinned one, and a pre-1.0 library that yanks is not one anybody should depend on.

Each gets one final release whose `lib.rs` is a deprecation notice and nothing else, pointing at the module inside `ton-net` that replaced it. After that they stop moving. `docs/release-process.md` records that the five are frozen and why.

## 8. The record that rejected this, answered

`NET-ADR-009` did not overlook one crate. It considered it and refused it, at `docs/adr/NET-ADR-009-code-structure.md:102-105`:

> "**One crate for the whole client.** Rejected. A single library has no enforced layering, so the audit target is one undivided blob and a consumer that wants only the cell model pulls the transport and the network with it. The flat layered crates give the reviewer a bounded target and the consumer a base crate it can take alone."

Two reasons. Both are answerable, and one of them turned out to be false about the tree it was written for.

**"A single library has no enforced layering."** Neither does this one. The layering is a shape in the manifests that nothing reads: adding `tokio.workspace = true` to `ton-net-block` clears every check in `just gate`, and `std::net::TcpStream` compiles there today with no manifest change at all. The premise is that the six crates enforce something. They do not, and section 2 is the demonstration. `scripts/check-layers.mjs` enforces more than the split ever did, including the four `std` reaches no dependency edge can see.

**"A consumer that wants only the cell model pulls the transport and the network with it."** This one is true of a naive merge and false of the one in section 5. `default-features = false` gives a consumer the cell engine, the typed structures, the proof engine, `Verified`, address parsing and the config reader, with no tokio, no socket and no transport in the graph. That is more than `ton-net-cell` alone gives them today, not less, and it is one dependency line rather than a choice between five.

What the record gets right and this plan keeps: the reviewer wants a bounded target. The bound moves from a crate boundary to a module boundary with a check on it, which is where `NET-ADR-009`'s own decisions 4 and 5 already put the currency, `pub(super)` at `:67-76`.

**This supersedes `NET-ADR-009` decisions 1 through 3 and the alternative above.** Decisions 4 through 7 stand unchanged and are what the module tree of section 4 follows. `NET-ADR-002:78,151` and `NET-ADR-008:16,39-45` carry the same six-crate statement and are edited with it.

## 9. The size of the move, measured

Every number here was counted, and where a count is a floor rather than a measurement it says so.

| | count |
|---|---:|
| crate-path occurrences to rewrite (`ton_net_x::`) | **237** |
| of those, cross-crate rather than self-references | **116** |
| inside `///` or `//!` doc comments, so real compile units | 134 |
| path edits needed in `bindings/node` | **0** |
| `pub` items declared across the six crates | 451 |
| of those, already on a private module path and therefore already unreachable | 362 |
| **`pub` items that genuinely lose a boundary** | **89** |
| `pub` items reached by nothing at all, a floor on what can drop | 93 |
| integration test targets | 17 |
| **test target name collisions** | **1**, `mainnet`, three ways |
| `#[test]` function names across the workspace | 569 |
| **cross-crate test-name collisions** | **0** |
| fixture files | 16, 680,647 bytes |
| **fixture pairs that are byte-identical and dedupe** | **4**, 101,871 bytes removed |

Three of these change the shape of the work.

**The binding needs no edits.** `bindings/node/src/lib.rs` names `ton_net::` twenty-three times and names none of the five lower crates. It moves through this migration untouched.

**The visibility work is 89 items, not 451.** `ton-net-cell`, `ton-net-lite` and `ton-net` declare every root module private, so 362 of the 451 `pub` items are already unreachable from outside their crate and changing their keyword is cosmetic. The items that genuinely lose a boundary sit in the three crates that declare `pub mod` at their root: `ton-net-tl` (32), `ton-net-adnl` (22), and `ton-net-block`'s four public modules (28).

**The 93 that nothing reaches are not all free to drop.** Some are named in a `pub use` list and are therefore published API with no in-tree user, so removing them is a breaking change to a published crate rather than a cleanup. And the 93 is a floor: 49 of the items counted as reached have names too generic for a grep to separate a real call from a collision (`new`, `len`, `parse`, `hash`, `verify`), so the true figure is higher and needs type information to settle.

## 10. The migration, as one pull request

Ordered so the tree compiles at as many points as it can, and so history survives.

1. `git mv crates/ton-net core`, then `git mv` each of the other five `src` trees into `core/src/` at its new path, one commit per source crate, no content edits. History follows the file. Two of the six are not straight renames: `ton-net-block` splits across `tlb/` and `proof/`, and `ton-net`'s own root files split between `client/` and the crate root.
2. Turn each moved `lib.rs` into the module's body file beside its directory, `tlb.rs` beside `tlb/`, and dissolve it into the parent where it only re-exported. Not `mod.rs`: the tree the six crates already use is the file-beside-directory form, and mixing the two forms inside one crate is the kind of inconsistency a reader pays for.
3. Rewrite paths: `ton_net_cell::X` becomes `crate::cell::X`, and so on for the other four. This is the largest mechanical step and it is the one to review by count rather than by eye.
4. Drop cross-crate `pub` to `pub(crate)` or `pub(super)` wherever the item has no external user, per `NET-ADR-009:67-69`, which already names `pub(super)` as the currency a child exposes to its parent.
5. Give each base64 decoder the doc sentence naming its domain, per section 6. They are not merged and neither moves.
6. Feature-gate `adnl/`, `lite/`, `client.rs`, `client/sync.rs` and `client/send.rs` behind `net`. `verified.rs`, `address.rs`, `config.rs`, `proof/` and `client/proof.rs` stay ungated, which is what gives the browser target the three capabilities section 5 names.
7. Merge `tests/` trees. One target collides, `mainnet`, three ways, and becomes `mainnet_adnl`, `mainnet_lite`, `mainnet_client`. No `#[test]` function name collides across crates, so nothing else renames. Four fixture pairs are byte-identical and dedupe to one copy each, removing 101,871 bytes of 680,647. Merge `benches/`; `cells`, `dict` and `verify` do not collide.
8. One `Cargo.toml` at `core/`. Workspace `members` drops to `core` and `bindings/node`, and `default-members` to `core`.
9. `deny.toml`, `about.hbs`, the notices, and the release workflow.
10. `scripts/check-versions.mjs`, `docs/release-process.md`, `docs/architecture.md`, `docs/api-design.md`, `docs/design/system-design.md`, `NET-ADR-008`, `NET-ADR-009`.
11. `scripts/check-layers.mjs` and its `just gate` entry, per section 3, reading `core/src/` rather than six crate roots.
12. Split the `Transport` trait out of `adnl/transport.rs` so the socket can be gated without it, per section 5.
13. The five deprecation releases, per section 7.

## 11. The floor: what proves the move changed nothing

The whole risk of this migration is a semantic change smuggled in under a mechanical one. Three things bound it, and all three are commands.

**`cargo test -p ton-net --test epoch`, unedited.** `crates/ton-net/tests/epoch.rs` pins the accept and reject boundary of the public verifier as a transcript. If the migration alters what the verifier accepts, that test is what says so. Its first line is the verification epoch, which stays 2, per `NET-ADR-008:56-60`: this migration accepts no new kind of proof and changes no acceptance condition.

**Every existing test passes with only its import paths changed.** Not rewritten, not relaxed, not deleted. A test that has to be edited to pass is the migration changing behaviour, and each one is reported rather than adjusted.

**The fixture hashes do not move.** `crates/*/tests/fixtures/` holds captured mainnet bags whose parses are asserted as exact equalities. They are the same bytes before and after.

Plus the standing floor: `just gate` green, and `just wasm` replaced by the `--no-default-features` build of section 5.

## 12. What this does not do

- It does not merge the binding. `bindings/node` stays its own crate, published as `ton-net-node`, with its own MSRV of 1.88 against the library's 1.85 (`justfile:172-174`). It is also the one place in the repository that needs no path edit at all, per section 9.
- It does not change any public type, function signature, or wire behaviour. A consumer's `use ton_net::X` keeps working; a consumer's `use ton_net_cell::X` does not, which is why the five get a deprecation release rather than silence.
- It does not raise the verification epoch.
- It does not settle where seed-phrase import lands. That is the v0.5.0 plan's, and this migration is what makes it a placement question rather than a publishing one.

## 13. The cost that is real, and not talked out of

**Incremental compile time, and the worst case is 42.7 to one.** An edit inside `ton-net-lite` today recompiles 541 lines. After the merge it recompiles 23,077. Six crates compile in parallel and cache independently; one crate is one compilation unit. The workspace already shares a single `target/` with no `.cargo/config.toml` override, so dependency artifacts are shared today and nothing changes there; what is lost is six independently cacheable units.

A second cost rides with it: `criterion`, `proptest` and `ed25519-dalek` are dev-dependencies of two crates today, so `cargo test -p ton-net-lite` builds none of them. After the merge every `cargo test` does.

Both are accepted because the alternative has been paid in a different currency: a published artifact per module, and a design question turned into a release question.

**One docs.rs page for 23,077 lines.** Module docs carry more weight after this, not less.

**Two accepted records stop being true** and are edited in this change rather than in a record of their own, the same way the signer-seam wording was.
