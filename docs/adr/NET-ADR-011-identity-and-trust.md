---
id: NET-ADR-011
title: What a cell's identity is, and the barrier a trusted hash may not cross
status: accepted
date: 2026-07-26
supersedes: none
superseded-by: none
---

# NET-ADR-011: What a cell's identity is, and the barrier a trusted hash may not cross

## Context

ton-net exists to verify answers against validator signatures rather than trust a server
(NET-ADR-001). NET-ADR-003 fixes the type discipline that keeps the claim honest: a verified
value has a private constructor and is a distinct type from a server-reported value, and no
operation turns a server-reported value into a verified one. The tree realizes both halves.
`Verified<T>` in `crates/ton-net/src/verified.rs` has no public constructor; its `new` is
`pub(crate)`, and because the definition spells the method name without the type's, a grep for
`Verified::new` across the workspace returns the call site alone,
`crates/ton-net/src/client.rs:384`, and not the definition. `ServerReported<T>` is the other
half, defined in `crates/ton-net-lite/src/types.rs` and re-exported from the facade, and the
two are separate types with no conversion between them.

Underneath that discipline sits the value the checks reduce to. A cell's identity is the set of
representation hashes and depths that its own parts and its children give it. The hash at level
zero is what a parent references and what a proof reproduces, and a proof is checkable because
the level-zero hash of a pruned copy of a tree equals the level-zero hash of the full tree. The
hash at the cell's own level is what `Cell`'s `PartialEq` compares, so it is the value two
cells are the same cell by. The two part company on any cell with a non-empty mask, which is
886 of the 1121 cells in the block fixture, and the case that gives the split its meaning is
the pruned branch, whose level-zero hash belongs to the subtree it replaced. A signature check,
a proof walk, and an anchor comparison each end in a comparison of one of those hashes against
another.

Today those hashes are computed and not accepted, and what makes that a fact rather than a
habit is a single construction site. `Cell::from_parts` in `crates/ton-net-cell/src/cell.rs`
takes a payload, a bit count, references, a kind, and a level mask, and its signature carries
no hash. It calls `summarize`, which checks the mask against `implied_mask` and then calls
`compute` in `crates/ton-net-cell/src/cell/hash.rs`, which does the SHA-256 work. A `Cell` is
an `Arc<Inner>` and nothing else, and a grep for `Arc::new` across `crates/ton-net-cell/src`
returns one line, inside `from_parts`, so a `Cell` value is that call's output or a clone
sharing its allocation, and either way it was hashed on the way into existence. `from_parts` is
`pub(crate)`, and a grep for `from_parts(` across the same directory returns five lines: its
definition, `Builder::finish` in `crates/ton-net-cell/src/builder.rs`, the eager build in
`read_and_build` and the on-demand build in `build_at`, both in
`crates/ton-net-cell/src/boc/parse.rs`, and the crate's property tests in
`crates/ton-net-cell/src/proptests.rs`.

`Builder::build` is the only public method on `Builder` whose return type is a cell, and it
derives the level mask from the references rather than taking one. `Builder::finish`, which
takes a kind and a mask and returns a cell as well, is `pub(crate)`. Three places in the
crate's non-test code call it, and only one of them is the pruned branch: `build` itself, for
an ordinary cell at the mask it just derived; `covering_cell` in
`crates/ton-net-cell/src/merkle.rs`, for a Merkle proof or update at the covered masks shifted
down one; and `pruned_branch` in `crates/ton-net-cell/src/usage.rs`, for a pruned branch at
`0b001`. Naming a mask is not being believed about it. Each of those three reaches `summarize`
through `from_parts`, and `summarize` holds the named mask to `implied_mask` before a byte is
hashed. Several public functions elsewhere in the crate return a cell, `virtualize`,
`create_proof`, `create_update`, `apply_update`, `combine_updates`, `rebuild_with_refs`,
`UsageTree::prune`, `UsageTree::prove`, `Slice::to_cell`, `BocView::cell`, `LazyBoc::cell`, and
the feature-gated `json::from_json` among them, and each of them reaches a cell through
`from_parts` or through a cell it was handed, because the construction site named above is
where a cell comes from.

The mask is checked rather than assumed, because it is hashed into the identity.
`implied_mask` gives a pruned branch its own stored mask, a library reference zero, a Merkle
cell `children_mask >> 1`, and an ordinary cell `children_mask`. A Merkle cell therefore does
not end a mask. It drops the mask one level and the mask goes on reaching upward from there.
A shift takes a mask to zero for two inputs and no others, `0b001` and `0b000`, so a mask stops
at a Merkle cell when what sat below was significant at level one alone, or was not significant
at any level to begin with. The fixtures hold a stop and a drop side by side, and what decides
between them is the mask below rather than the kind of cell carrying it. The Merkle update in
`crates/ton-net-cell/tests/fixtures/block-basechain.hex` covers two ordinary cells at `0b001`,
a mask they took from the pruned branches somewhere below them, and the shift takes that to
empty. The Merkle update in `crates/ton-net-cell/tests/fixtures/account-proof.hex` covers two
pruned branches at `0b011`, and the shift takes that to the `0b001` the update itself carries.

The pruned branch is held to zero references in `classify` in
`crates/ton-net-cell/src/boc/parse.rs`, alongside a check that its two copies of the mask
agree, that its mask is non-zero, and that its length is two bytes plus thirty-four per marked
level and no more.

Where a bag carries hashes of its own, they are checked and not substituted. `check_stored` in
`crates/ton-net-cell/src/boc/parse.rs` compares a cell's stored hashes and depths against what
its contents give and refuses on a mismatch. A grep for the name returns its definition and
three call sites: the read that builds a bag's cells, the read that keeps an identity per cell
in place of a cell, and the on-demand build that `BocView::cell` and `LazyBoc::cell` both reach
through `build_at`. The third is the path a resolver runs on, which is why it is named here
rather than folded into the other two.

None of that is a corner case, on a count taken over the block fixture in
`crates/ton-net-cell/tests/fixtures/block-basechain.hex`. The bag holds 1121 cells, of which
886 carry a non-empty level mask. 830 are ordinary and 597 of those are masked, 289 are pruned
branches, one is a library reference, and one is a Merkle update whose own mask is empty
because the shift in `implied_mask` took it there. The account proof is 45 cells, 41 of them
masked, and 22 of the 45 are pruned branches. Level-mask arithmetic and pruned branches are the
ordinary traffic of a block, not an exotic path a decision can afford to treat as rare.

Two pressures now bear on that arrangement, and this record settles them before either
arrives.

One is scale. The cheapest way to make a large bag finalize quickly is to believe the hashes
it carries about itself instead of recomputing them. Other clients offer that mode, and under
it a stored hash that disagrees with the real one is accepted. The mode is a real option with
a real payoff, and the question is not whether to forbid it forever but what keeps it from
eating the property the client is built to hold.

The other is the seam. A store keyed by a subtree's identity, a reader that presents a bag
through a window rather than as a slice, and a resolver that loads a subtree on demand each
have to name a subtree's identity before they hold the subtree. Of those three, one is decided.
NET-ADR-012 settles a synchronous read-at storage seam, along with the memory budget a parse
takes, the determinism of how finalization is dispatched, and the discipline a performance
claim is held to. Its seam is a window on a bag's bytes, not a view of a cell graph backed by a
store, and it decides neither a store keyed by identity nor a resolver. This record reads
neither into it. Those two are work this record serves and no record
has yet required.

What carries that seam today is `Identity` in `crates/ton-net-cell/src/cell/hash.rs`,
re-exported from `crates/ton-net-cell/src/lib.rs` and returned by `Cell::identity`. Its fields
are private and it is read through `level_mask`, `count`, `hash`, `depth`, `hash_at`,
`depth_at`, and `repr_hash`. The type is already doing the seam's job inside the crate:
`verify_roots` in `crates/ton-net-cell/src/boc/parse.rs` keeps one `Identity` per cell instead
of a cell and feeds them back through `summarize`, which is what lets `BocView::verify`
hash-check a bag whose graph would not fit.

Keeping this record and NET-ADR-012 apart is deliberate and belongs on the record: a later
amendment that raises a throughput number must not be able to edit trust text, and two
separate records make that mechanical rather than a matter of a reviewer's attention.

Parts of what follows are decided approach rather than present behaviour, in the manner of
NET-ADR-007. No trusting parse mode exists, no resolver exists, and no store keyed by identity
exists. Where a decision requires a change to the tree rather than describing it, that is said
in place.

## Decision

**1. A cell's identity is computed from its data, its kind, its level mask, and its children,
and is not supplied; any future path that accepts a supplied identity is a distinct, named,
non-default path.**

The identity of a cell is the set of representation hashes and depths `compute` derives from
the cell's own parts and its children's identities, under the level rules of the cell model. It
is established once, when the cell is built, and a `Cell` is immutable from there.

What enforces it today is not a convention but a chokepoint. `Cell::from_parts` is
`pub(crate)`, its signature carries no hash, it computes through `summarize`, which refuses a
level mask the children do not imply before any hashing happens, and it holds the crate's
single `Arc::new`. A function that returns a cell got it from there or from a cell it was
already holding.

The crate has no constructor that takes an identity's hashes as arguments. Two functions derive
one: `compute` in `crates/ton-net-cell/src/cell/hash.rs`, and `summarize` in
`crates/ton-net-cell/src/cell.rs`, which checks the mask and hands back what `compute` gives
it. Both take a cell's own parts and its children's identities. Two more make an `Identity`
value without deriving anything, and neither leaves the crate: `Identity::blank` is private and
is the room `compute` fills through the equally private `set`, and the `NONE` constant beside
them is `pub(crate)` and is what a reference slot holds before a child is put in it. There is
one place a value the cell did not derive enters an identity, and it is the cell model's own
substitution rule rather than a back door: `compute` reads a pruned branch's lower-level hashes
and depths out of the branch's body, which is what lets a pruned tree hash to the root of the
full tree. Decision 3 says what that value is worth and on what footing, and the footing is not
that the crate computed it.

If a path that accepts an identity from outside is ever built, it is a separately named
constructor, not a parameter added to the present one and not a default. A parameter on
`from_parts` would turn each of its existing call sites into a call site of the trusting path,
and the distinction would then live in the arguments rather than in the name.

**2. No parse that trusts the hashes a bag supplies may reach a constructor that produces a
`Verified` value.**

A scale-oriented mode that accepts a bag's stored hashes rather than recomputing them is not
forbidden. What is forbidden is that its output be indistinguishable, in the type system, from
the output of a checked parse. The rule is a reachability rule and it is checkable by reading
the call graph: from an entry point that trusts a supplied hash, there is no path to
`Verified::new`.

Three things enforce it, and two of them hold today.

`Verified::new` is `pub(crate)` in `crates/ton-net/src/verified.rs`, so a caller outside the
`ton-net` crate has no way to produce a `Verified`: the constructor is crate-private, the
fields are private, and none of its three other inherent methods returns one. Inside the crate
the one call site is `crates/ton-net/src/client.rs:384`. That is the same private-constructor
enforcement NET-ADR-003 fixes for proven reads, and this record extends its reach rather than
inventing a second mechanism.

`ton-net-cell` lists `sha2` and `thiserror`, with `serde_json` and `lz4_flex` optional behind
features, and names no workspace crate. Under the dependency layering NET-ADR-009 fixes it
sits at the base. A parse mode added in the cell crate is therefore unable to name `Verified`,
let alone construct one, and the enforcement is the absent dependency edge rather than
anyone's diligence.

The third is the part that must be built when the mode is, and the absent edge shapes it. That
same missing dependency puts `ServerReported` out of the cell crate's reach in the same way it
puts `Verified` there: `ServerReported<T>` is defined in `crates/ton-net-lite/src/types.rs`, a
layer above the base. So a trusting parse in `ton-net-cell` surfaces its roots in a type that
crate defines for the purpose, distinct from what a checked parse returns and with no operation
converting one into the other. Carrying that type into the `ServerReported` family happens
where the family exists. The facade already re-exports `ServerReported` from
`crates/ton-net/src/lib.rs` and already holds one, because the bytes came back inside it, and
`ServerReported::try_map` is public and carries the wrapper onto a value read out of it, which
is what `crates/ton-net/src/client.rs:290` does today for a decoded account. `ServerReported`'s
own constructor is `pub(crate)` to `ton-net-lite`, so the facade maps a wrapper it was handed
and does not mint one, and a mode that has no wrapper to map is served from `ton-net-lite`
rather than by opening that constructor. A caller that wants a proof out of such a bag reparses
it under the checked path. The distinction is carried by the type, so a reviewer reading a
proof path sees a compile error rather than having to re-derive which flag was set upstream.

The budget refusal of NET-ADR-012 is bound by this. A parse that runs short of budget refuses.
It does not proceed by checking less, and in particular it does not proceed by believing the
bag.

**3. A lazy subtree stands as a pruned branch; resolving one is a verification against a value
the parent commits to, and a hash mismatch is a refusal.**

A lazy subtree needs no mutation and no interior mutability. The placeholder is a real pruned
branch: an unexceptional TON cell, hash-complete like any other, whose body carries the hash
and depth of the subtree it stands in for. `compute` already substitutes those stored values
below the branch's own level, which is what makes a Merkle proof checkable, so the proof engine
already depends on this cell doing this job. Beside the graph sits a table from hash to loader,
and it sits beside the graph rather than inside a cell.

It follows that a parent built over placeholders has a computed identity under decision 1,
with no special case for it. The parent hashed its children's stored hashes and depths, which
is what `compute` hashes for a parent in general, and the pruned branch supplied the values
the full subtree would have supplied.

The trust status of a resolved subtree divides cleanly, and the division is the point of this
decision.

Loading a subtree and finding that its level-zero hash equals the hash the pruned branch it
replaces carries is a verification. The value on the other side of that comparison came out of
the bag and not out of a hash the crate took: `compute` reads a pruned branch's substituted
hashes and depths straight from the branch's body through `read_hash` and `read_depth`, and
computes only the branch's own level hash. What makes the value trustworthy is not its
provenance but its binding. At level zero the parent hashes the branch's stored hash directly,
and at the parent's own level the parent hashes the branch's own-level hash, which `compute`
takes over the branch's descriptors and body, where that stored hash sits, so either way the
value is inside the parent's identity. The parent's identity roots to an
anchor under NET-ADR-005 and NET-ADR-006 and is carried by `Verified`. Where the parent's
identity roots to no anchor, the placeholder's hash is a value the same untrusted source chose,
and matching it shows the loader and the bag agree. The loaded bytes are themselves parsed
under decisions 1 and 2, so the subtree's own hash is computed from its contents and not read
out of whatever the store appended.

What substitution preserves is the parent's level-zero hash and not its representation hash. A
parent holding a pruned branch and a parent holding the real subtree are deliberately not equal
cells, which `Cell`'s own `PartialEq` states on the type: a pruned branch is not equal to the
subtree it replaced, though the two share a level-zero hash. The masks are why. An ordinary
cell's mask is the union of its children's under `implied_mask`, and a pruned branch carries a
mask of its own, so the parent over the placeholder is significant at a level the parent over
the real subtree need not be, and `repr_hash` reads at the cell's own level. So the resolution
gate is an equality on the level-zero hash at each step, and an equality on the root's
representation hash once every placeholder is resolved, when the resolved root and the
whole-parse root are the same cell.

Loading a subtree whose hash does not match is a refusal. It is a typed error, not a warning,
not a log line, and not a fallback to the placeholder. A refused load is retained in no part,
and the resolver does not try a second source and take whichever answers. A loader is a store
or a server, and neither is trusted; a mismatch means one of them is wrong or lying, and
continuing past it is the behaviour the client is built to refuse.

What resolution does not do is prove the parent. A matching hash says the subtree is the subtree
the parent committed to. Whether the parent is anything is the anchor's question, settled by
NET-ADR-005 and NET-ADR-006 and carried by `Verified`.

**4. The identity type is public API, at a fixed minimum surface, and its fields are private,
so a caller outside the crate can neither construct one nor alter one.**

The seam is the identity of a cell read back without a rehash, and that is `Identity`, which
`Cell::identity` returns. It stays public. A store keyed by identity, a reader presenting a bag
through a window, and a resolver loading a subtree on demand each have to name a subtree's
identity before they hold the subtree, and the alternative to a named type is a loose hash and
a loose mask passed alongside each other, which loses the pairing of hash to depth to level
that the level rules are defined over.

The minimum surface is what the type carries now and no more: the level mask, and one hash per
level the mask makes significant and one besides, lowest first, with the depth beside each
hash. `count` is that number, `level_mask.count_ones() + 1`, so a pruned branch marking one
level has two hashes rather than one. A reference's identity is the same call on the reference,
so the type carries no copy of its children's. No provenance, no loader handle, no bag offset,
no cursor. Those belong to whatever holds the cell, and putting them on the identity would let
two cells with the same identity compare unequal.

The fields are private, and that is what decision 1 needs at the public boundary. `level_mask`,
`hash0`, `depth0`, and `extra` are reached through the accessors named above, so outside the
crate a struct literal for an `Identity` is a compile error and so is an assignment to one of
its fields. An identity that crosses the seam is therefore one the crate produced, and a caller
cannot take a genuine one, overwrite the hash, and hand it back as a subtree's identity.

Privacy is the mechanism and `#[non_exhaustive]` is not, which is worth stating because the
marker is the reflex reach for this property and it does not carry it. `#[non_exhaustive]`
blocks a struct literal, an exhaustive destructuring, and an exhaustive match from outside the
defining crate. It does not make a public field read-only: a caller holding a genuine value of
such a struct can assign to any public field it has and hand the value back, which is the
forgery a supplied identity would be. The marker does load-bearing work where a public field or
a public variant would otherwise be part of the shape a caller may rely on, which is why
`CellError` carries it in `crates/ton-net-cell/src/error.rs` and why `MasterchainInfo` carries
it beside its public fields in `crates/ton-net-lite/src/types.rs`. The workspace also carries it
on types whose fields are already private, `Verified` in `crates/ton-net/src/verified.rs` and
`ServerReported` in `crates/ton-net-lite/src/types.rs` among them, and there it is not what
holds anything: on a struct a caller can neither construct nor destructure, the marker adds
nothing to construction, to mutation, or to the freedom to add a field. So the marker is
neither required nor forbidden on `Identity`, and no part of this record rests on it.

`summarize` is the crate's other route to an identity, and it is not publicly reachable: it is
`pub` inside a private module, and no re-export in `crates/ton-net-cell/src/lib.rs` names it,
so
`ton_net_cell::summarize` does not resolve outside the crate. It stays that way. It takes
children's identities rather than hashes, so publishing it would hand out no supplied-identity
path, but it is the function that decides whether a mask is one the children imply, and that
belongs to the construction chokepoint rather than to a caller.

What committing to this at 1.0 costs is stated rather than left implicit. Under NET-ADR-008 a
change a consumer sees in the observable surface is an API break, and after 1.0 that forces a
major release. Private fields leave room to add one later without a break, which is a second
reason they are the right shape and not only a safety one. Removing an accessor or changing
what one returns stays a break, which is why the surface is fixed at the minimum above and a
consumer wanting more is escalated under the consumer-priority guard of NET-ADR-001 rather than
served by growing the type.

## Alternatives considered

- **A boolean trust-the-stored-hashes flag on the parse path, on the parse options
  NET-ADR-012 decides or anywhere else.** Rejected, and this is the option the record exists
  to refuse. A flag is a value, and a value flows: it is set at one call site and read at
  another, and the paths between them have to be re-derived by hand to know which mode ran.
  The result type is the same either way, so a downstream reader has no signal to branch on,
  and the `Verified` discipline of NET-ADR-003 silently stops meaning what it says. The check
  falls to the reviewer rather than to the compiler, and it has to be repeated on any change
  that touches the call graph. A type rule inverts those three: the barrier is checked
  once, by the compiler, at each call site at once.
- **A debug assertion or a runtime check that a trusting parse is not on a proof path.**
  Rejected. It fires after the fact, on the paths that happen to be exercised, and a release
  build with assertions compiled out is the build that ships. A barrier absent in the
  configuration that matters is not a barrier.
- **Trusting a bag's stored hashes on the scale path outright.** Rejected here, and
  NET-ADR-012 rejects it downstream on this record's authority. It is the cheapest available
  speedup for a large bag, and it buys the speed with the property the crate is built to hold.
- **Returning a trusting parse's roots in the `ServerReported` type itself.** Rejected,
  because the cell crate cannot reach it. `ServerReported` lives in `ton-net-lite`, and the
  dependency edge that keeps `Verified` out of `ton-net-cell` keeps `ServerReported` out
  identically. The cell crate names its own untrusted-root type and the facade maps it into
  the family one layer up, where the family exists.
- **`#[non_exhaustive]` on the identity type as the thing that keeps a caller from forging
  one.** Rejected on a reading of what the marker does. It blocks a struct literal, an
  exhaustive destructuring, and an exhaustive match; it does not stop a caller from taking a
  genuine value and overwriting a public field. Private fields are what stops both, and they
  are what the type has.
- **Keeping the identity private and passing loose values across the seam.** Rejected. A
  `[u8; 32]` and a mask travelling separately lose the pairing that the level rules are
  defined over, and the mistake it invites first is a hash read at one level beside a depth
  read at another.
- **Interior mutability in `Cell` so a lazy child can be filled in after the parent is
  built.** Rejected. A cell's identity is computed at construction, so a cell whose children
  can change afterwards either carries a stale identity or has to rehash itself and its
  ancestors. `Cell` clones share one `Arc`, so such a mutation would be visible through the
  handles already handed out, including ones a caller believes it is holding constant. The
  pruned branch needs neither: it is a legitimate cell with a legitimate identity, and the
  side table is an ordinary map.
- **Warning and continuing when a loaded subtree's hash does not match its placeholder.**
  Rejected. The mismatch is the signal, and a client that logs it and proceeds has taken a
  server's or a store's word over a hash it computed itself, which is the inversion
  NET-ADR-001 forbids.
- **Deciding the barrier inside NET-ADR-012, alongside the scale decisions.** Rejected. A
  performance amendment would then open a record that also holds the trust rule, and the two
  would be revised together by whoever cared about the number. Separate records mean a
  throughput change reaches the trust text by editing this record, which is a visible act
  rather than a side effect.

## Consequences

- The default parse recomputes the hashes, and no option makes it stop. This forbids a
  trust-the-stored-hashes flag, on the parse options NET-ADR-012 decides or anywhere else,
  that returns the type a checked parse returns. That is the likeliest shape of a future scale
  change and the shape this record is written to catch.
- A trusting mode, if it is built, is a second result type and a second set of paths through
  the crate. That duplication is a real cost and the record accepts it: the alternative is one
  path whose meaning depends on an argument.
- A public constructor in the cell crate may not take a hash. This forbids adding a hash
  parameter to `Cell::from_parts` or to `Builder::build`, forbids publishing `summarize`, and
  forbids an `Identity` a caller assembled, which is what the type's private fields
  mechanically prevent.
- A resolver does not get to skip hashing. The subtree it loads is parsed under the checked
  path like any other bytes, so the win from a lazy subtree is in the subtrees left unloaded
  rather than in loading them cheaply. A design that expected the second is ruled out here
  rather than after it is built.
- A resolution gate compares level-zero hashes, not representation hashes, until the last
  placeholder is gone. A gate written as an equality on the parent's representation hash at
  each step would fail on correct resolutions, because the parent's mask changes when the
  placeholder under it does.
- A hash mismatch on resolution ends the operation. This forbids a resolver that retries
  against another source and accepts whichever answers, and forbids a partial result assembled
  from the subtrees that did match.
- `Cell` stays immutable and free of interior mutability, so a lazy reader keeps its built
  cells beside the graph. `LazyBoc` already does this: its cells sit in the reader, in a
  `RefCell` the reader owns, and `crates/ton-net-cell/src/boc/lazy.rs` states the reason on the
  module.
- The identity surface is frozen at the minimum. A consumer that wants provenance, an offset,
  or a loader handle on the identity is escalated under NET-ADR-001 rather than served by
  widening the type, because those fields would make identity depend on where a cell came
  from.
- Adding a trusting mode is a behavioral break under NET-ADR-008. A bag whose stored hashes
  disagree with what its contents give is refused today, and under such a mode it would pass,
  which is the "something refused now passes" half of what that record calls a behavioral
  break, and that record fixes such a break as breaking whether or not the API moved with it.
  `VERIFY_EPOCH` is the number NET-ADR-008 tracks that move with, and the transcript it pins
  over the public verifier is what decides whether the number rises. That mechanism is
  NET-ADR-008's and is not re-decided here.
- Much of this holds in the tree today. What does not is the distinct result type for a
  trusting mode and the resolver in its entirety; the verification section separates the two.

## Chain scope

TON-specific in what it governs, general in form. The cell, the representation hash, the level
mask, the pruned branch, and the substitution that makes a Merkle proof checkable are TON's
own, and so is the bag of cells whose stored hashes decision 2 refuses to trust. The barrier
itself, that a value produced under weaker checking may not reach the constructor of a value
claiming stronger ones, is not a TON idea, but it is fixed here for the TON cell engine of
NET-ADR-002. Composing several chains lives above ton-net, in the consumer (NET-ADR-001).

## Custody and security

No user keys, no funds, no signing, no recovery. The cell engine hashes bytes. Custody is
untouched, and the position of NET-ADR-001 and NET-ADR-003 is unchanged.

The security surface is the read path in its entirety, because the checks this client makes
end in a hash comparison and this record fixes what a hash is allowed to be. A cell whose
identity was supplied rather than computed makes the comparisons above it vacuous: a proof
walk still runs, a signature set still verifies, and the answer still comes back marked
proven, while the value it was proven about is whatever the bag said it was. That is the
failure the barrier is built to keep out of reach, and it is a failure with no symptom, which
is why the enforcement is a type rule rather than a check.

Three properties carry it. Identity is computed at construction through one crate-private
constructor whose signature has no hash in it. A trusting parse has no route to
`Verified::new`, which is held by a private constructor in one crate and by a dependency edge
that does not exist in the other. And a resolved subtree is admitted against a value the parent
committed to and the anchor covers, with a mismatch ending the operation rather than degrading
it.

The third deserves a careful reading, because the value a resolution compares against is a
value the bag wrote. A pruned branch's substituted hash is read out of the branch's body. It is
worth trusting only through what it is bound to, which is the parent's identity, and only as
far as that parent's own root reaches under NET-ADR-005 and NET-ADR-006. Resolving a
placeholder in a graph no anchor covers shows that the store and the bag agree, which is a
statement about those two and not about the value.

The parts of this that are not yet built are named in the verification section, and no
sentence in this section should be read as a description of a trusting mode or a resolver that
exists.

## Verification

Checkable now, against the tree:

- `Cell::from_parts` is the crate's cell chokepoint. A grep for `Arc::new` across
  `crates/ton-net-cell/src` returns one line, inside it. It is `pub(crate)`, its parameters are
  a payload, bits, references, kind, and mask, and a grep for `from_parts(` over the same
  directory returns five lines: its definition, `Builder::finish`, `read_and_build` and
  `build_at` in `crates/ton-net-cell/src/boc/parse.rs`, and the crate's property tests.
- The level mask is checked before anything is hashed. `summarize` compares the stored mask
  against `implied_mask` and returns `CellError::Malformed` on a disagreement, and the pruned
  branch, library reference, Merkle, and ordinary cases are each spelled out there.
- A Merkle cell lowers a mask rather than ending it, which the two block fixtures and the
  account proof show from both sides: `children_mask >> 1` takes `0b001` to empty in each block
  fixture's Merkle update, whose two sides are ordinary cells, and takes `0b011` to `0b001` in
  the account proof's, whose two sides are pruned branches.
- `Builder::build` derives the mask from the references, and a grep for a public method on
  `Builder` returning a cell returns it alone. `Builder::finish`, which takes a kind and a
  mask, is `pub(crate)`, and its callers outside the tests are `build`, `covering_cell` in
  `crates/ton-net-cell/src/merkle.rs`, and `pruned_branch` in
  `crates/ton-net-cell/src/usage.rs`.
- A bag's own hashes are checked and not substituted. `check_stored` in
  `crates/ton-net-cell/src/boc/parse.rs` compares stored hashes and depths against the computed
  ones and refuses on a mismatch; a grep for the name returns its definition and three call
  sites, in `read_and_build`, in `verify_roots`, and in `build_at`, which is the on-demand build
  behind `BocView::cell` and `LazyBoc::cell`.
- A pruned branch is held to zero references, to a non-zero mask, to two agreeing copies of
  that mask, and to a length of two bytes plus thirty-four per marked level, in `classify` in
  `crates/ton-net-cell/src/boc/parse.rs`.
- `Verified::new` is `pub(crate)`, and because the definition does not spell the type name, a
  grep returns the call site alone, `crates/ton-net/src/client.rs:384`. `Verified<T>` has no
  public constructor and its fields are private.
- `ton-net-cell` lists `sha2`, `thiserror`, and the optional `serde_json` and `lz4_flex`, and
  no workspace crate, so it has no route to `Verified` and none to `ServerReported`, which is
  defined in `crates/ton-net-lite/src/types.rs`.
- `Identity`'s fields are private and its accessors are the whole of its read surface, so an
  external struct literal and an external field assignment are both compile errors.
  `Identity::count` is `level_mask.count_ones() + 1`, so a pruned branch of mask `0b001` has
  two hashes.
- `summarize` is not publicly reachable: it is `pub` in the private `cell` module and
  `crates/ton-net-cell/src/lib.rs` re-exports `Cell`, `CellType`, `Identity`, `MAX_BITS`, and
  `MAX_REFS` without it.
- The identity type already carries the seam's job inside the crate. `verify_roots` keeps a
  `Vec<Identity>` in place of a graph, and `crates/ton-net-cell/tests/allocations.rs` grades
  the difference as an exact equality: building a bag costs verifying it plus one allocation
  per cell built.

Gates on the work this record decides, none of which runs today:

- The reachability check: a test or a lint asserting that an entry point which trusts a
  supplied hash has no path to `Verified::new`. Until a trusting mode exists the property
  holds vacuously, and the gate is what keeps it holding on the day one is added.
- The distinct-result-type check: a trusting parse's roots come back in a type the cell crate
  defines and the checked path does not accept, asserted by a compile-fail test rather than by
  review, and the facade's mapping of that type into the `ServerReported` family is asserted
  where the mapping lives.
- Resolution parity: a graph resolved from placeholders has the same root representation hash
  as the same graph parsed whole, and each intermediate step matches on the level-zero hash,
  both asserted as equalities.
- Resolution refusal: a loader that returns a subtree with any other hash produces a typed
  error, retains no part of it, and leaves the placeholder in place, asserted over the hostile
  corpus in `crates/ton-net-cell/tests/cell/hostile.rs` rather than over a happy-path fixture,
  in the shape its depth test already uses: acceptance asserted on one side of the boundary
  and an exact `CellError` value on the refusing side.
- The construction check: an external struct literal for an `Identity`, and an external
  assignment to one of its fields, are both compile-fail cases.
