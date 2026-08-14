---
id: NET-ADR-012
title: What the cell engine promises at scale
status: accepted
date: 2026-07-26
supersedes: none
superseded-by: none
---

# NET-ADR-012: What the cell engine promises at scale

Parts of this record describe the tree as it stood when the decision was taken, and some of
that has since been built. What moved is at the end, under [Since acceptance](#since-acceptance);
the text above it is left as it was written, except where a claim about the tree was found
false and corrected, which is marked in place.

## Context

The cell engine was built for a wallet reading proofs, where a bag is a few kilobytes. The
fixtures it is graded against run from about one and a half kilobytes for the account proof to
thirty-seven for the basechain block, and the crate states their sizes itself: the
account proof the hostile corpus mutates is 45 cells and the basechain block, the larger of
the two block fixtures, is 1121, both counted in the table on
`crates/ton-net-cell/tests/allocations.rs`. The engine is also the floor under every consumer
that reads a cell. NET-ADR-009 puts `ton-net-cell` at the base of a one-way layering,
depending on no other workspace crate, and two crates above it name it in their manifests,
`ton-net-block` and the `ton-net` facade, with the Node binding reaching it through the
facade. `ton-net-adnl` and `ton-net-lite` do not name it, because they carry the transport
and the query layer and never open a bag. The edge NET-ADR-011 rests a type barrier on is the
other one: `ton-net-cell` names no workspace crate at all, so a parse mode added there can
reach neither `Verified` nor `ServerReported`. NET-ADR-001 fixes that the tie between
consumers breaks toward indexer and
node scale, and an indexer reads whole states and whole blocks rather than a proof of one
account.

How much larger those are is not a number this repository holds, and none is invented here.
What it does hold is its own ceiling. `MAX_CELLS` is `1 << 17` in
`crates/ton-net-cell/src/boc.rs`, and on the figure that constant's own note carries, about
250 bytes of live heap for a parsed cell, one parse that reaches the ceiling holds roughly
31 MiB. That is two orders of magnitude above the largest fixture, it is a bound per call
rather than in total, and a study of the gap between it and what the engine was shaped for
produced questions the tree has no answer to.

Four of them are settled here. What a caller may say about the memory a parse takes. How a
bag larger than memory is reached at all. Whether the way finalization is dispatched can be
seen in what a caller gets back. And what may be claimed about performance, on the strength
of what measurement.

The present state, read from the tree rather than assumed:

- Parsing has no options. `parse_boc(bytes: &[u8])` in
  `crates/ton-net-cell/src/boc/parse.rs` is one function, and the bounds it enforces are the
  crate constants `MAX_CELLS` and `MAX_DEPTH` in `crates/ton-net-cell/src/boc.rs`. Both are
  `const`, so a caller cannot move either, and no path counts a running total of anything.
- Every entry point that reads a bag takes a byte slice: `parse_boc`, `BocView::open`,
  `LazyBoc::open`, `file_hash`, and `compress`, `decompress`, and `decompress_boc` behind the
  `compress` feature. The three that walk a bag's cells reach them through one shared
  `Reader`, held in the `boc.rs` trunk and handed down; the other four take the slice whole
  and never open it as cells: `file_hash` hashes it, `compress` compresses it, and
  `decompress` and `decompress_boc` expand it, the second handing its expansion to
  `parse_boc`. **Corrected against the code:** the feature's fourth function, `compress_boc`,
  takes root cells rather than a bag, so it is not an entry point for one and this list,
  whose subject is the entry points that read a bag, does not name it. A bag larger than
  memory cannot be presented to this crate in any form, because there is no form to present
  it in.
- Finalization is a single pass, and `ton-net-cell` runs no parallelism. Its dependencies are
  `sha2` and `thiserror`, plus `serde_json` and `lz4_flex` behind the `json` and `compress`
  features, and no runtime among them. Its dev-dependencies are `criterion` and `proptest`,
  which the benchmarks and the property tests use and the library does not reach.
- Failure order is not uniform. `read_raw` runs forward over the cells and reports the
  lowest-index failure; `check_depths`, `read_and_build`, `verify_roots`, and the build loop
  in `build_at` each run in reverse and report the highest-index one. `build_at` also walks
  the subtree its cell reaches before that loop runs, off a stack, and reports a bad
  reference in whatever order the stack pops. `CellError` in
  `crates/ton-net-cell/src/error.rs` carries no cell index in any of its variants, so today a
  caller cannot tell which cell failed at all.
- Allocations are counted, and that is new since the questions above were asked.
  `crates/ton-net-cell/tests/allocations.rs` installs a counting global allocator and holds
  four readings to it. The gap between building a bag and verifying one is asserted as an
  exact equality, one allocation per cell built. The per-cell shape of a read is asserted as
  a bound with a stated slack of sixteen over a measured six, so a regression that is per
  cell fails while a vector growing one step differently does not. And a second read of the
  same bag is asserted to cost what the first did. What that file does not measure is a
  parse's peak residency, which is what a memory bound would have to be denominated in.
- Timing measurement is criterion wall-clock, in `crates/ton-net-cell/benches/cells.rs` and
  `benches/dict.rs`.

NET-ADR-011 is upstream of this record. It fixes the barrier between an identity this crate
computed and one a bag asserted about itself, the barrier
`crates/ton-net-cell/src/boc/parse.rs` realizes in `check_stored`, where a cell's stored
hashes and depths are checked against what its contents give and are used in place of them on
neither of its two call sites, reached from `read_and_build` and from `verify_roots`.
**Corrected against the code:** this read three call sites, naming `build_at` as one of them.
A grep returns two, and `build_at` reaches the first through `build_one` without naming
`check_stored` itself.
Scale is where that barrier is under the most pressure, because the cheapest way to make a
large bag finalize quickly is to believe what it says about itself. This record does not
reopen the barrier. Every decision below is taken on the computed side of it, and where a
decision is constrained by it that is said in place.

What this record settles, and what it leaves open, is the division NET-ADR-011 draws. That
record names three consumers of the identity seam: a store keyed by identity, a reader
presenting a bag through a window, and a resolver loading a subtree on demand. Only the
second is decided here, alongside the memory budget a parse takes, the determinism of how
finalization is dispatched, and the discipline a performance claim is held to. The seam below
is a window on a bag's bytes rather than a view of a cell graph backed by a store. Neither a
store keyed by identity nor a resolver is decided by this record, and no sentence in it should
be read as deciding one.

Much of what follows is decided approach rather than present behaviour, in the manner of
NET-ADR-007. Two of the names below are proposed by this record rather than found in the
tree, and are written without backticks for that reason: ParseOptions, the options value
decision 1 introduces, and parse\_boc\_with, the entry point that would take it. A search
returns no definition of either. A storage seam and a parallel finalization path are likewise
absent: nothing in the workspace hashes cells on more than one thread, and the lockfile
carries no data-parallelism crate. What the tree does hold is an async runtime, which is a
different thing and worth naming so the next reader does not read this as more than it says.
`ton-net` takes tokio for its timer alone, its dev-dependencies and its examples take
tokio's executor to drive the async client, and the Node binding takes napi's. None of that
reaches `ton-net-cell`, which depends on no workspace crate and names no runtime.

The word budget is a different matter, and the search for it is not empty. A per-link work
budget is spent on the signature path in `crates/ton-net-block/src/chain.rs`, where
`carried_weight` bounds curve operations at twice the validator set size so a set padded with
copies of one signer cannot amplify compute; NET-ADR-006 fixes it and the threat model
records it. `crates/ton-net-adnl/src/connection.rs` carries a frame budget on the answer to a
query, and the prefix dictionary calls a key width a budget. Each of those bounds work at its
own layer. What does not exist anywhere is a memory budget on the parse path, which is the
object decision 1 names, and the shared word is worth saying out loud so a later reader does
not take one for the other.

## Decision

**1. Parsing takes options, and the memory bound is a budget the parse consumes rather than a
limit it may spend again.**

ParseOptions is a value in the `boc.rs` trunk, where the read path, the view, and the lazy
reader all reach it through the parent (NET-ADR-009). `parse_boc` keeps its present signature
and delegates to parse\_boc\_with under the default options, the shape `serialize_boc` and
`serialize_boc_with` already have in `crates/ton-net-cell/src/boc/serialize.rs`.

The part that matters is not the options surface. It is that the memory bound is denominated
in bytes and debited as the parse takes them, rather than being a ceiling each call may reach
independently. `MAX_CELLS` today is the second kind: it bounds one call, so N concurrent
replies can each spend it in full, and the bound a caller reasoned about is silently the bound
times N. The size of that gap is on the record in the crate already. The note on `MAX_CELLS`
states that a parsed cell is about 250 bytes of live heap while real proofs run 35 to 58 wire
bytes per cell, which is a four-fold to seven-fold expansion. The read path holds more than
the graph at its peak: `read_and_build` takes an `Arc<[u8]>` copy of the whole bag for its
cells to window into, then holds the raw form and the built graph at the same time, so the
peak carries all three alongside the caller's own slice. A cell count is a loose proxy for
bytes on top of that, and not for the reason it once was. A parsed cell's data is a window
on the one buffer the whole bag shares rather than a copy of its own bytes, and
`crates/ton-net-cell/src/cell/payload.rs` states the price of that on the module: keeping
one cell of a bag keeps the bag's bytes, and `MAX_CELLS` is what bounds how much that is. So
a count names neither the buffer a single retained cell pins nor the boxed hashes above the
lowest that a cell significant at more than one level carries.

A budget bounds what a parse holds while it runs, and is released when the parse returns. It
does not bound what a caller retains afterwards. A caller holding many graphs is bounded by
holding them, and that is visible where the caller made the choice. The record claims the
first property and not the second, and no sentence here should be read as a bound on total
residency.

The default, when a caller passes no options, is today's behaviour and may not be weaker than
it. It admits every bag `parse_boc` admits now and refuses everything it refuses now. Options
may tighten the bound below the default.

Raising a bound is a narrower permission than tightening one, and it is bounded on three
sides rather than left open. A raise is a named field set deliberately, so it appears at the
call site that chose it and does not arrive by default or by inheritance. A raised cell
ceiling is bounded above by the byte budget in force, so a caller that names a ceiling of
`usize::MAX` gets a parse that refuses the moment its bytes are spent rather than one that
allocates until the process dies. That ordering is the point: the byte budget is the bound
that holds, and the cell ceiling is a cheaper check in front of it, so raising the cheap one
cannot widen what the parse may actually take. Without it the option would be a denial of
service written into the API on a path fed by a liteserver the client does not trust.

`MAX_DEPTH` may not be raised at all, by any option and to any value. It is a stack-safety
bound rather than a memory one, and the difference is that no budget a caller sets changes the
stack. The constant's own note says it keeps a deep graph from overflowing the stack when the
cells are later walked or dropped, and those walks are the load-bearing part. They are
spread across the crate rather than gathered in one place, and the ones that carry the most
depth include `collect_forks`, `validate_node` and `traverse_node` in
`crates/ton-net-cell/src/dict.rs`, which recurse once per fork down a cell graph, and
`prune_cell` in `usage.rs`, `graft` in `merkle/update.rs` and `render` in `cell/dump.rs`,
which recurse once per reference. Those are instances rather than the whole set, which is
part of why the bound sits at the parse rather than at each walk. A key
width bounds the dictionary walks too, but a caller choosing a wide key does not make the
graph shallower, so what a parse admits is what those walks descend.

A budget refusal is a new variant on `CellError`, which the enum's `#[non_exhaustive]`
attribute already admits without breaking a caller. Refusal is the only response. A parse that
runs low on budget fails; it does not proceed by dropping a check, and in particular it does
not proceed by believing a bag's stored identity values, which NET-ADR-011 forbids.

**2. Storage is reached through a synchronous read-at seam, and a concurrent reader gets its
own window.**

The seam is a trait in the `boc.rs` trunk with a read-at method and a length,
blanket-implemented for a byte slice so every path that works today keeps working unchanged.
It is a window on a bag's bytes. It is not a view of a cell graph backed by a store, and it
carries no identity: a store keyed by a subtree's identity and a resolver that loads a subtree
on demand are the two seam consumers NET-ADR-011 leaves open, and this decision leaves them
open too.

It is synchronous, and the cell crate stays free of any runtime. NET-ADR-002 fixes a sans-I/O
core with I/O behind one narrow trait at the edge, and that trait, `Transport` in
`crates/ton-net-adnl/src/transport.rs`, is where async lives. NET-ADR-009 puts `ton-net-cell`
at the base of a one-way layering, depending on no other workspace crate. An async trait in
this crate would put an executor underneath the base, and a wallet that only wanted to parse a
proof would compile one to do it. A caller whose store is inherently async reads into a buffer
at its own edge and presents the buffer, which is the same division the transport seam already
makes.

The windowed reader is held to three things, each of them a check in the implementation
rather than a promise in this record. A read returns exactly the bytes at the offsets
asked for or an error, never short and never bytes from elsewhere. A window is checked against
the bag's length before any byte is read. And the bag is immutable for the reader's lifetime;
a store that can change underneath is outside the contract rather than handled by it.

A concurrent reader gets its own window. The trait takes a shared reference and holds no
cursor, and the cursor lives in the per-reader window value, so two readers of one bag never
queue behind each other. One window behind a lock would serialize readers with no reason to
contend and would make the cost of one lookup depend on where another reader had left the
cursor, which is what the gate below is built to measure.

One consequence falls out of the tree and is fixed here. `read_header` in
`crates/ton-net-cell/src/boc/header.rs` reads a bag's per-cell offset index and discards it,
on the stated ground that the index only repeats where each cell starts, which the reader
already knows. Under a windowed reader that ground is gone: a reader that has not read the
cells does not know where any of them begins. So when a bag carries an index and the reader is
windowed, the index is retained. It is retained as a claim and not as a fact: an offset is
bounds-checked against the cell area before it is used, and the cell it lands on is hashed
from its own contents like any other. Seeking to a cell more cheaply must not mean believing
more about it, which is the same constraint NET-ADR-011 fixes for stored hashes.

The gate on this work is a read-amplification test: a counting reader records every offset and
length it is asked for, and the test asserts the exact byte total and the exact ranges a named
lookup pulls on a fixture. That is a better gate than any timing assertion, because the number
is a property of the algorithm and is identical on every machine, while a duration is a
property of the machine that ran it.

**3. Whether a bag is finalized sequentially or in waves is not observable in any result,
including in which error comes back.**

Wave-parallel finalization is planned in `docs/plan/v0.4.0.md`. It changes the order in which
cells are hashed, and that order must not reach a caller.

The rule is that the lowest cell index wins. Among the cells of a bag that fail, the failure
reported is the one at the lowest index in the bag's stored order, whatever order the work
actually ran in, and whatever a worker happened to reach first.

The other answer is available, and it is what a scheduler-order report gives: whichever
failing cell a worker reached first in wall-clock time, so a bag with two bad cells reports a
different error run to run on the same bytes. That is a defensible choice for a program whose
errors are for a log. It is not available here, because the error taxonomy is a published
stability commitment. `CellError` is public and re-exported from the crate root; NET-ADR-008
fixes that a release whose public API moved in a way the version bump does not admit is
refused; and NET-ADR-002 fixes that the Node binding takes its error codes from the core's own
list, so a core error resolves through a closed enumeration rather than a table of its own. An
error that depends on scheduling is not a stable surface: a caller that branches on the variant
takes a different branch run to run, and no version number describes the change.

This is a change in the tree and not a description of it. The forward pass reports the lowest
index today, but the four descending passes report the highest and the reference walk ahead
of the build loop in `build_at` reports in stack order, so the rule requires each of them to
reduce toward the lowest failing index rather than return at the first failure it reaches.

The gate is parity, and it runs over the hostile corpus rather than the happy path. A bag with
no failing cell cannot distinguish any of these rules from any other, so a happy-path parity
test would pass under the behaviour this decision exists to forbid. The corpus in
`crates/ton-net-cell/tests/cell/hostile.rs` is the right ground: it mutates a real proof with
flipped bytes, truncations, and splices from a fixed-seed generator, so a failure reproduces
exactly.

Two things are added to it, and what they add is stated against what the file already holds.
Of its six tests, five work from arbitrary or mutated bytes, and each of those five keeps
only what parsed and discards the error: four assert that nothing panics, and
`what_survives_reserialization_parses_back` also asserts that what parsed reserializes and
reads back to the same representation hash. The sixth test in the file,
`a_bag_deeper_than_the_limit_is_refused`, reads both sides of the limit and is the only one
that names an exact `CellError` value: acceptance at the limit itself, and
`CellError::TooDeep { limit: MAX_DEPTH }` one link past it. It builds its bag deliberately
rather than mutating one. So no bag that a mutation caused to be refused has the error it
produced asserted anywhere in the file, and that is the assertion the parity gate needs.

The two additions are bags carrying more than one independently failing cell, which the
corpus does not deliberately construct today, and the comparison itself: `CellError` derives
`PartialEq` and `Cell` implements it, so the parallel result and the sequential result can be
compared as values, error included. The depth test names its exact error through a pattern
rather than an equality, but the `boc.rs` unit tests already compare a whole `parse_boc`
result against an expected `Err` with `assert_eq!`, so the derive the gate rests on is one
the tree exercises.

That gate supersedes the one `docs/plan/v0.4.0.md` states for the same work. The plan gates
wave-parallel finalization on byte-for-byte agreement with the single-pass finalization on
real mainnet bags. Real mainnet bags parse, so that is a happy-path test, and the Alternatives
section below rejects a happy-path parity test by name for the reason given above: every
failure-selection rule agrees on a bag with no failing cell. Agreement on bags that parse is
kept as a floor, because a wave that changed an identity would be a worse fault than a wave
that changed an error. It is not the gate.

**4. A performance claim in this crate is held to an allocation count, not to a stopwatch.**

An allocation-regression test is the gate on any layout or sharing change: a named workload's
calls asking the allocator for memory are counted, and the count is asserted. The reason is
that the measurement is deterministic. On a fixed toolchain the same code asks the allocator
for memory the same number of times run after run, which the gate asserts rather than
assumes, while wall-clock on a thermally constrained laptop does not repeat even against
itself. A change that claims to reduce allocation is graded by the count it claims to
reduce.

This part is built. `crates/ton-net-cell/tests/allocations.rs` is the gate, and the shape of
its assertions is part of the decision rather than an accident of how it was written. Where a
count can be pinned exactly it is pinned exactly: the difference between building a bag and
verifying one is asserted as an equality against the bag's cell count, and its comment says
why a bound with room in it would let a regression through. Where the quantity being held is a
per-cell rate rather than a total, the assertion is a bound over that rate with a slack
constant stated in the file and measured at six, which fails on anything per cell and does not
fail on a vector growing one step differently. A count is also asserted to repeat across two
reads of the same bag, because a measurement that moves is not one.

The counting allocator lives in a test target rather than the library, because implementing
one means installing a global allocator and that means `unsafe`, which the library forbids at
`crates/ton-net-cell/src/lib.rs` with `forbid(unsafe_code)`. That attribute stands on its own
and carries no note; the note that draws this line is on the test target itself, which says
that the library forbids unsafe code and goes on forbidding it, and that a test binary is a
crate of its own.

The criterion benchmarks stay. They are not the gate.

A timing number may still be worth having, and some work has no allocation count that would
show what it did: a change that hashes the same cells on several threads moves a duration and
not a count. The rule for taking a duration is that a control workload must contend for the
same resource as the thing it controls. A control that runs on idle hardware measures nothing
about the hardware under load. The worked counterexample: in one study a SHA-256 control held
its figure steady while the workloads measured beside it slowed by half, and the reading
that the machine was quiet was wrong. That chip runs a hash on a unit of its own, so the
control was never contending for what the other work was contending for, and a control that
cannot slow down cannot report that anything else did.

So: a timing number is not claimed unless it was taken with an in-run control that is valid by
that test. Absent one, the change is described by what it does rather than by how fast it
went.

This supersedes the second gate `docs/plan/v0.4.0.md` states on wave-parallel finalization, a
measured speedup on the large-bag benchmark. A criterion figure taken twice on one laptop is
exactly the shape this decision refuses, and leaving it standing would leave two opposite gates
live on one piece of work. The requirement is not dropped: the speedup is measured against an
in-run control that contended for the same resource, or the change ships described by what it
does. Between them, this decision and decision 3 replace both of the plan's gates on that
item. The plan is to be amended to match; the amendment has not been made, and until it is
this record is what governs the item.

## Alternatives considered

- **A per-call limit rather than a consumed budget.** Rejected. It is what `MAX_CELLS` is
  today, and its failure is the one this record opens on: N concurrent parses each spend the
  ceiling in full, so the effective bound is the stated bound times a number the bound does
  not mention. The per-call constants are kept as a floor underneath the budget, not as the
  whole answer.
- **A raisable cell ceiling with no bound over it.** Rejected. An option a caller may set to
  `usize::MAX` on a path fed by an untrusted liteserver is a denial of service written into
  the API, and the consequence that no option makes the default weaker does not cover it,
  because a raise is a caller weakening its own parse rather than the default. The raise is
  kept, because a consumer reading a state cannot work under a bound set for a wallet reading
  a proof, and it is bounded above by the byte budget in force so that the widened check is
  the cheap one and not the one that holds.
- **A raisable depth bound alongside the raisable cell ceiling.** Rejected. Depth bounds the
  stack rather than the heap, and a byte budget does not bound recursion. The recursive walks
  named in decision 1 descend whatever a parse admitted, so raising the depth bound raises how
  far they recurse with nothing underneath to stop them.
- **An async storage trait.** Rejected. It puts an executor beneath the base of the layering
  NET-ADR-009 fixes, so every consumer of the cell model compiles a runtime, including a
  wallet that only parses a proof and never touches a store. It also contradicts the sans-I/O
  core of NET-ADR-002, which puts I/O behind one trait at the edge and keeps the layers below
  it free of sockets and clocks. A caller with an async store adapts at its own edge, where
  the existing `Transport` already sits.
- **Trusting a bag's stored hashes and depths on the scale path.** Rejected under
  NET-ADR-011. It is the cheapest available speedup for a large bag and it buys the speed by
  giving up the thing the crate exists to provide. A budget that runs low is a refusal, not a
  licence to check less.
- **A process-wide budget in a static.** Rejected. An ambient global cannot be scoped to one
  consumer, is invisible at the call site that spends it, and makes two unrelated users of the
  library contend for a bound neither of them declared.
- **One shared window behind a lock.** Rejected. It serializes readers that have no reason to
  contend, and it makes the byte cost of one lookup depend on another reader's position, which
  is the measurement the read-amplification gate depends on being stable.
- **A timing assertion as the regression gate on a layout change.** Rejected. It is not
  reproducible across machines, so it either fails on a slow machine for no reason or is
  loosened until it detects nothing.
- **Testing dispatch parity on the happy path.** Rejected, and this is the gate
  `docs/plan/v0.4.0.md` states today. A bag with no failing cell produces the same result
  under every failure-selection rule, so the test passes under exactly the behaviour it was
  written to forbid.

## Consequences

- A caller can bound the memory a parse takes, and a caller running many parses against one
  budget gets one total rather than one ceiling per parse. The bound covers the parse's own
  peak and not a retained graph, and the record says so rather than letting the stronger
  reading stand.
- The default parse is unchanged. A caller that passes no options gets what it gets today.
- An option may tighten any bound. An option may raise the cell ceiling, deliberately and
  under the byte budget in force, and it may raise nothing else. A caller that raises the
  ceiling has widened a cheap pre-check and not the bound that holds, which is why the raise
  is not a way to make a parse unbounded.
- `MAX_DEPTH` is not a caller's to raise, at any value and under any budget. A consumer that
  needs a deeper graph than the engine will walk is escalated under the consumer-priority
  guard of NET-ADR-001 rather than served by an option, because the recursive walks the bound
  protects are not bounded by anything else the caller sets.
- The cell crate stays free of a runtime, so a storage backend whose read is inherently async
  cannot be plugged in directly. It is adapted at the caller's edge, and this record accepts
  that cost as the price of keeping the base layer synchronous.
- The seam decided here carries bytes and not identities, so a store keyed by identity and a
  resolver remain undecided. NET-ADR-011 says the same from its side, and a design that needs
  either takes its own record rather than reading one into this seam.
- Wave-parallel finalization cannot land without the parity gate. A speedup that changes which
  error a bag produces is not a speedup that ships, and the gate that decides is the hostile
  corpus rather than the fixtures that pass.
- `docs/plan/v0.4.0.md` needs amending where it states the gates on wave-parallel
  finalization, and this record governs the item until that lands. Its byte-for-byte
  agreement on real mainnet bags becomes a floor under the corpus parity gate rather than the
  gate, and its measured speedup on the large-bag benchmark becomes a figure taken with an
  in-run control or not taken at all.
- The four descending passes and the walk ahead of the build loop in `build_at` change shape.
  Reporting the lowest failing index means reducing across the failures rather than returning
  at the first one reached, which costs a full pass over a bag that was going to be refused
  anyway.
- A performance claim has a named form of evidence, and part of it is already running. A
  layout or sharing change is graded against `crates/ton-net-cell/tests/allocations.rs`; a
  duration is reported only alongside a control that contended for the same resource. A number
  without one is not published, which forbids the most common shape of performance claim in
  this area: a benchmark run twice on a laptop.
- Of the four decisions, one is built and three are not. The allocation gate exists; the
  budget, the seam, and the determinism rule do not, and the verification section separates
  what is checkable now from what is a gate on work not yet done.

## Chain scope

TON-specific in what it governs, general in form. The bag of cells, its offset index, its
cached hashes, and the identities the engine computes over them are TON's own. The budget, the
read-at seam, the determinism rule, and the measurement discipline are not TON-specific ideas,
but they are fixed here for the TON cell engine of NET-ADR-002. Composing several chains lives
above ton-net, in the consumer (NET-ADR-001).

## Custody and security

No user keys, no funds, no signing, no recovery. The cell engine parses bytes and computes
hashes over them. Custody is untouched, and the position of NET-ADR-001 and NET-ADR-003 is
unchanged.

The security surface this record touches is the read path, which is an untrusted boundary: a
bag arrives from a liteserver the client does not trust. Three of the four decisions land on
it.

The budget is a denial-of-service bound. Today's bound is per call, so concurrency multiplies
it, and the decision is that the bound must be spendable once rather than once per reply. The
refusal is typed and it is the only outcome; a parse short of budget does not continue with
fewer checks.

Because the budget is a denial-of-service bound, the option that raises a bound is part of the
same surface and is bounded in decision 1 rather than left to a caller's judgement. A raised
cell ceiling sits under the byte budget in force, so the widened check is the cheap one; the
depth bound is not raisable at all, because it guards the stack and no byte budget guards a
stack.

The storage seam must not weaken identity. A cell reached through a window is hashed from its
own contents exactly as a cell reached through a slice is, and a retained offset index is a
claim to be bounds-checked rather than a fact to be acted on. Reading less of a bag must not
mean believing more of it, which is the barrier NET-ADR-011 fixes and this record works inside.

The determinism rule protects the error taxonomy, which is a security-relevant surface and not
only an ergonomic one: a caller that distinguishes a malformed bag from a truncated one is
making a decision, and a variant that depends on thread scheduling makes that decision
non-reproducible on identical bytes.

Except for the allocation gate, these are properties the decisions require of the code rather
than properties the code holds today. No budget, seam, or determinism rule is implemented, and
no sentence in this section should be read as a description of present behaviour.

## Verification

Checkable now, against the tree:

- Parsing has no options and no running total. `parse_boc` takes bytes alone, and `MAX_CELLS`
  and `MAX_DEPTH` are crate constants a caller cannot move.
- Both existing limits are asserted by test. The cell-count refusal is pinned in the `boc.rs`
  unit tests, before anything is allocated for the count, and the depth refusal is pinned in
  `crates/ton-net-cell/tests/cell/hostile.rs` at the limit and one link past it, as an exact
  `CellError` value on the refusing side.
- The crate holds no runtime. Its manifest lists `sha2` and `thiserror`, with `serde_json` and
  `lz4_flex` optional behind features; `criterion` and `proptest` are dev-dependencies the
  library does not reach.
- Failure order is not uniform today. The forward pass, the four reverse passes, and the
  stack walk ahead of the build loop in `build_at` are all visible in
  `crates/ton-net-cell/src/boc/parse.rs`.
- No mutation test asserts which error a refused bag produced. The five tests in
  `crates/ton-net-cell/tests/cell/hostile.rs` that read arbitrary or mutated bytes keep only
  what parsed, and the one test that names an exact error value,
  `a_bag_deeper_than_the_limit_is_refused`, builds its bag rather than mutating one.
- `CellError` derives `PartialEq` and is `#[non_exhaustive]`, so the parity comparison the
  determinism gate needs is available, and the budget variant can be added without a breaking
  change.
- The allocation gate runs. `crates/ton-net-cell/tests/allocations.rs` counts every call that
  asks the allocator for memory on the test thread, an allocation or a reallocation and not a
  free, pins the building-minus-verifying difference to the bag's cell count as an equality,
  bounds the per-cell rate of a read against a stated slack, and requires a second read of a
  bag to cost what the first did.

Gates on the work this record decides, none of which runs today:

- The default-parse equivalence: a bag parses identically with default options and with no
  options across the fixtures and the hostile corpus, so the default is provably not weaker
  than today's.
- The budget under concurrency: one budget handed to several parses admits in total what one
  parse at the ceiling admits, and the parse that would exceed it is refused with a typed error
  rather than allocating.
- The raise is bounded: a parse whose cell ceiling is raised to `usize::MAX` under a byte
  budget refuses on the byte budget, asserted as the typed refusal rather than as an absence
  of a crash, and no option compiles that moves `MAX_DEPTH`.
- Read amplification: a counting reader asserts the exact byte total and the exact ranges a
  named lookup pulls, on a fixture, as an equality.
- Dispatch parity: for every bag in the hostile corpus, including bags built to fail at more
  than one cell, the parallel path returns a value equal to the sequential path's, error
  included.
- Any timing figure that is published names the control it was taken against and shows that
  the control moved with the load.

## Since acceptance

Decisions 3 and 4 have since been built, and what was built differs from what this record
anticipated in three places worth naming. Decision 2 is untouched: no storage seam exists.

**Decision 1 is half built: the tightening half, without the budget.** `ParseOptions` is in
the `boc.rs` trunk with `parse_boc_with` beside `parse_boc`, and `open_with` beside `open` on
both `BocView` and `LazyBoc`. It carries the cell ceiling and nothing else, and it can only
lower it. What this record calls the part that matters, a bound denominated in bytes and
debited as the parse takes them, is not built, and neither is the raise that record admits
only underneath one. So the ordering this record fixes is intact rather than discharged: a
raise cannot land before the budget it has to be bounded by.

The ceiling is applied at `read_header`, which has three non-test call sites, one for each
way into a bag. That is `NET-ADR-009`'s rule about a bound holding on every path rather than
anything this record asked for, and it is what the shipped gate tests.

**Decision 3 is built, and the gate did not land where this record put it.** The lowest
failing index now wins in the three passes that judge cells: the `finalize` call in each of
`build_planned` and `verify_planned`, and the descending build loop in `build_at`, all in
`crates/ton-net-cell/src/boc/parse.rs`. Each reduces through a `Lowest` and discharges it at
the end rather than returning at the first failure it meets.

The reference walk ahead of that loop is the exception, and this record asked for it to change
too. It still returns at the first failure it meets, in stack order, and it was left alone
because it cannot be reached: `read_raw` refuses a reference that is not a forward index
inside the bag before `build_at` runs, and `build_at` bounds the index it is handed, so every
position the walk visits is one the header already held. Its refusal is a branch kept against
a future edit, not a site that reports.

The parity gate is `the_wave_plan_and_a_single_pass_agree_on_corrupted_bags`, and it sits in
the unit tests of `boc/parse.rs` rather than in `crates/ton-net-cell/tests/cell/hostile.rs` as
this record said it would. The comparison drives both plans over one reading of a bag, which
takes `build_planned`, `verify_planned`, `heights` and `Waves`, and those are private to the
module and re-exported nowhere. From outside it, a bag can only be read the way the public API
reads it, which is one plan. It mutates the same captured proof with the same
single-flipped-bit generator, and it pins what the corpus reached as equalities: 3,225 bags
reach the finalizing pass and 54 are refused there, so a corpus that quietly stopped refusing
fails rather than passes.

It compares three things where this record's gate named one, the parallel result against the
sequential. The third is that building a bag and verifying it refuse it alike. It went in
because deleting the failure check from the identity-only read left the suite green on the
tree it was written against, with `BocView::verify` then accepting a bag `parse_boc` refuses.

That reason no longer holds on its own, and this section records it rather than repeating it.
`a_bag_read_five_ways_reaches_the_same_answer`, in
`crates/ton-net-cell/tests/cell/fuzz/targets.rs`, landed between the branch's base and its
merge and catches the same mutation, so the suite is not green under it today. The comparison
is kept because it holds the agreement on a fixed corpus from inside the module that picks the
plan, where the fuzz target reaches it through the public API.

The corpus also turned out unable to grade the rule it was chosen for. Of the 54 bags it
refuses, every one fails at a single cell, because a flipped bit in a proof changes a hash
without refusing anything, and one failure is picked the same way by every selection rule.
What grades the rule is `a_wave_wide_enough_to_split_reports_the_lowest_failure`, which builds
its bag and plants two faults of different kinds.

**Decision 4's gate has grown, and its shape has not.**
`crates/ton-net-cell/tests/allocations.rs`
held four readings when this record was written and holds seven: a lookup, a walk and a write
over a dictionary joined the four over a bag. Its slack over a bag read is measured at eight
rather than the six stated above, and the file now names the eight one at a time where it used
to give the figure alone. It states a second slack of four over a dictionary walk. Counts that
can be pinned exactly are still pinned exactly and rates are still bounded, which is what this
decision fixed.

**The plan amendment this record was waiting on has landed.** `docs/plan/v0.4.0.md` now states
that this record governs the gates on wave-parallel finalization, so the closing sentence of
decision 4, that the amendment has not been made, no longer describes the tree.

The Consequences items that turned on those two are discharged with them. Wave-parallel
finalization landed with the parity gate rather than without it, and the passes that item said
would have to change shape have changed shape: a bag is finalized under a plan now, and the
descending order is one plan among them rather than the only way a pass runs.
