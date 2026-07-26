# Fuzzing

## What is fuzzed

The decode boundary of `ton-net-cell`: the point where bytes a peer chose become values
this client trusts. A bag of cells arrives from a liteserver nobody vouches for, every
length, count and index in it was written by whoever sent it, and a Merkle proof is
attacker-shaped by design. That is why the crate root forbids unsafe code and denies
`unwrap`, `expect`, `panic`, `unreachable`, `todo` and slice indexing (NET-ADR-003).

A lint rules out one way of failing. The fuzzer looks for the rest, over inputs nobody sat
down and wrote. The targets live in `crates/ton-net-cell/tests/cell/fuzz.rs` and its
`fuzz/targets.rs` child.

## The mechanism, and why not cargo-fuzz

`cargo-fuzz` drives libFuzzer, and libFuzzer needs a nightly toolchain for its sanitizer
flags. `rust-toolchain.toml` pins stable, and every Rust job in
`.github/workflows/ci.yml` names `stable`, `1.85.0` or `1.88.0`. A nightly-only target
here would be a target nothing in this repository runs, which is worse than no target: it
reads as coverage and provides none.

What runs on stable is a target set plus a driver. Each target is a plain `fn(&[u8])` over
one hostile byte string. A deterministic loop generates those byte strings from a corpus of
captured mainnet bags and hands them over one at a time. The targets are the part worth
keeping: the signature is the one every coverage-guided driver consumes, so a nightly or an
AFL job added later reuses them rather than rewriting them.

It adds no dependency. `deny.toml` refuses a second copy of a crate already in the tree and
vets every license and advisory, so a crate is a decision here rather than a line in a
manifest (NET-ADR-004). `proptest`, already in the tree for the properties in
`crates/ton-net-cell/src/proptests.rs`, generates values rather than mutating captured
bytes, so it answers a different question and is left where it is.

## Running it

The whole battery, at the budget the gate runs:

```
cargo test -p ton-net-cell --all-features fuzz
```

That is five targets at fifteen hundred cases each, about four seconds. It runs inside
`just gate` and inside the `check` job of CI, because it is part of `cargo test`.

A longer run sets the budget:

```
TON_NET_FUZZ_ITERATIONS=250000 cargo test -p ton-net-cell --all-features fuzz -- --nocapture
```

Two hundred and fifty thousand cases per target ran in about seven minutes on the machine
this was written on, with the five targets in parallel as `cargo test` runs them by
default. An hour at that rate is around two million cases per target. `--nocapture` is what
shows the per-target report of how many cases got past the reader, which is the only way to
see what a run covered rather than only that it finished.

The scheduled job in CI runs a million cases per target nightly, next to the mutation
testing and for the same reason: the answer does not change between two commits on the same
day.

Run the long campaign in the default profile rather than `--release`. Debug builds check arithmetic
overflow, and an overflow on a length read off the wire is one of the failures worth
finding. `--release` wraps instead, which turns that failure into a wrong value nothing
reports.

## Reproducing a failure

A failing case prints the target, the seed, the case index and the input as hex before the
assertion message. The whole run is a function of the seed, so:

```
TON_NET_FUZZ_SEED=0x53465546465a5a55 cargo test -p ton-net-cell --all-features fuzz
```

reproduces it exactly. The seed accepts decimal or a `0x` prefix and defaults to a fixed
value, so a failure in the gate reproduces from what the run printed rather than from
whatever the clock said.

For a case worth keeping, the printed hex goes into `crates/ton-net-cell/tests/cell/`
as its own named test asserting the property that broke. A fuzz corpus is not a regression
suite: the corpus moves, and a case that only reproduces under one seed and one budget is
not a check anybody can read.

## The targets

Each holds the reader to the properties that make the boundary sound, rather than to
having survived, which the test runner reports anyway.

- **`bag_of_cells`** runs `parse_boc` over the whole case. What parses has to sit inside
  `MAX_CELLS`, `MAX_DEPTH` over the reference graph, `MAX_BITS` and `MAX_REFS`, carry
  exactly the bytes its bit count needs, and hold to at most one cell per two bytes of
  input, which is the form the no-unbounded-allocation rule takes here: every cell costs
  its two descriptor bytes, and the header reader refuses a count the remaining bytes could
  not hold before it allocates for that count. What parses then round trips, to the same
  root representation hashes and to the same bytes twice running, for every bag but the one
  shape named below.

- **`header`** opens the same case through `BocView` and checks the counts it reports
  against the same bounds. It then reads the bag four ways, through `parse_boc`,
  `BocView::materialize`, `BocView::verify` and `BocView::cell`, and requires the same
  answer or the same error down all four. Those paths share a header reader and a cell
  reader and diverge in what they keep, so an input where they disagree is an input where
  one of them has a bound the others do not.

- **`slice_reads`** drives a `Slice` over the cells of a bag that parsed, with a read
  script taken from the case's own bytes. A read either moves the cursor forward inside the
  cell or fails having moved nothing. The second half of that holds for the primitive reads,
  which check their whole width before they move; a composite read is two reads, so
  `load_maybe_ref` can spend its bit and then find no reference, and it is held to the
  weaker rule on purpose.

- **`dictionary`** opens a cell of the bag as the root of a `Dict`, an `AugDict` and a
  `PfxDict` at a key width the case chooses, then looks a key up and walks. Every key a walk
  hands back is the dictionary's own width, and the keys arrive strictly ascending, which is
  the property a label read wrongly or a branch taken wrongly breaks first.

- **`compressed`**, behind the `compress` feature, runs `decompress` over a corpus of
  compressed bags. What comes back is no longer than the length the input's prefix names, a
  prefix naming four gigabytes is refused, and the compressed door and the plain one reach
  the same bag or refuse it the same way.

## The corpus

Three captured mainnet bags, in `crates/ton-net-cell/tests/fixtures/`: an account proof,
which carries exotic cells, and two whole blocks, which carry stored hashes and complete
dictionaries. Random bytes stop at the magic number and bytes that get past it stop at the
first count, so a corpus of real bags is what reaches the reference decoding, the exotic
classification and the stored-hash check at all.

Around those sit the two smallest bags that parse, the four combinations of the offset
index and the trailing checksum written out so both are reached whatever the fixtures
happen to carry, and one bag built by hand whose cells share their children.

A case is built four ways. Bytes with nothing behind them and bytes behind the magic number
cover the early refusals. A header written field by field puts a chosen reference size,
offset size, cell count, root count and cell-area size in front of real cell bytes, which
is where the accounting between those five is decided rather than where each is
range-checked. A corpus seed put through byte-level edits covers the rest.

Two repairs run after an edit, each most of the time and neither always. A bag states how
many bytes its cells take and the reader holds it to that statement, so an edit that
changes a bag's length is refused at the accounting and the bytes it changed are never
looked at. A bag may also carry a CRC-32C, and an edit under one is refused at the
checksum. Repairing both is what puts an edit in front of the cell reader; leaving them
broken some of the time is what keeps the two gates themselves under test.

Byte editing alone is not enough on this format. Measured over this corpus it got three
or four cases in a hundred past `parse_boc`: an edit lands on a cell descriptor about as
often as on cell data, and a changed descriptor moves every cell after it, so the bag stops
reading at the first one. So a case is as often derived through the cell model instead: a
subtree of a mainnet block serialized on its own is a valid bag whose root is a dictionary
node, a pruned branch or a Merkle proof, sometimes with its bits changed through a builder,
which puts the readers above the parser in front of real structure. That took the share of
cases reaching the reader to about a third for the bag targets and half for the header.

Each target reports that share and fails under a floor. Without it a fixture that moved, a
corpus that stopped reaching the reader or a repair that stopped repairing would leave
every target green while checking nothing past the first refusal.

## Where a check states less than it might

Three of the checks are narrower than the obvious wording, and each is narrow because of
what the code does rather than to make a run easier to pass. A check written wider than the
code holds is a claim the code does not prove, which is the one thing this repository asks
a contributor not to write.

A dictionary walk is not bounded by the size of the bag it walks. References point strictly
forward, which keeps the graph acyclic, and it does not stop two branches of a fork naming
the same next cell. A chain of such forks is a bag of `n` cells holding `2^(n-1)` entries,
so a walk over one runs for a length the bag's own size says nothing about. The harness
therefore caps the walk itself, and the corpus carries a small bag of that shape so the
capped path is exercised.

`decompress` returns a buffer no longer than the length the compressed input's prefix
names, and not necessarily one that long. The decoder underneath sizes its buffer from the
prefix, decodes into it, and truncates to what the body actually produced, so the prefix is
a bound on the expansion rather than a statement of it. The cap in front of that read is
what keeps the bound meaningful, and the target asserts the bound.

The round trip is checked for every bag except one, and that exception is a defect rather
than a property. A bag's root list may name one cell twice, so a bag can carry more root
entries than it has distinct cells; `serialize_boc` writes one root entry per root it was
handed against a cell count of the distinct cells it walked, and a header stating more
roots than cells is refused on the way back in. The `bag_of_cells` target names the case it
covers rather than covering a case it would fail, and the comment beside it says so.

## Adding a target

A target is `fn(&[u8]) -> bool`, taking the whole case and nothing else. Where it needs
choices beyond the bag, which read to make or which key width to open a dictionary at, it
takes them from a stream seeded by the input rather than from the driver, which keeps every
target a function of one byte string. That is what lets an edit explore the script as well
as the bag, and what keeps the shape a coverage-guided driver expects.

The return value answers whether the reader accepted the case. It feeds the floor above and
is not a verdict; a driver that does not want it drops it.

Assert properties, not survival. A target that only calls the reader is a test that the
process did not die, and `tests/cell/hostile.rs` already holds that ground over a corrupted
proof.
