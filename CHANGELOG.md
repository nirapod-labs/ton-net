# Changelog

Notable changes to ton-net. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the versioning is
described in [the roadmap](docs/roadmap.md): the Rust crates move in lockstep on
one library version, and SemVer is measured against the observable API and the
wire behavior, so a proof-verification change is breaking and an internal refactor
is not.

0.3.0 is the first registry release, the point at which a read no longer depends
on a block hash the caller has to supply. 0.1.0 and 0.2.0 are git tags and were
never published.

## [Unreleased]

## [0.4.0] - 2026-08-14

The cell engine at full capability: builders and slices without a gap between
what can be written and what can be read back, every dictionary variant, usage
trees, virtualization, Merkle proof and update creation, and the bag-of-cells
codec in every form this client meets. `VERIFY_EPOCH` rises to 2.

### Added

- `BocView::has_cache_bits`, reporting whether a bag's offset index carries a
  cache bit inside each of its entries. The flag decides how an entry is spelled,
  not whether one is there: under it an entry taken for a plain offset is the
  offset shifted. Both mainnet block fixtures set it, so it is the ordinary case.
  Nothing here reads the index, so it changes no read today; it is reported
  because a reader that retains the index cannot take an offset without it.

- The `ton-net` facade re-exports the cell types its own methods answer with:
  `Slice`, `Identity`, `Builder`, `CellError`, `Dict`, `DictEntry`, `DictIter`,
  `Lookup` and `MsgAddress`, beside the `Cell` and `CellType` it already carried.
  A consumer could call `Cell::parse`, `Cell::identity` or `Cell::to_boc` through
  the facade and had nowhere to put the result, because naming the type meant
  naming a crate the facade presents as internal. `parse_boc` and `serialize_boc`
  come with them, since `Client::account_state` hands a proof and a state back as
  raw bag bytes and a facade consumer could write a bag out and not read one back,
  as do `MAX_CELLS`, `MAX_DEPTH`, `MAX_BITS` and `MAX_REFS`. No feature of the cell
  engine is forwarded; `docs/api-design.md` says why for each.
- `just default-deps`, in the gate, asserting that the cell engine's default
  feature set names neither `lz4_flex` nor `serde_json`. The default build was
  already compiled and tested; what nothing asserted was that the two optional
  dependencies stay out of it, which held only as a consequence of two
  `optional = true` lines. NET-ADR-010 lists the lz4_flex half as a verification
  item.
- `base64_encode`, `base64_decode`, `hex_encode` and `hex_decode` in
  `ton-net-cell`, the two spellings a serialized bag and a cell hash travel in,
  with `CellError::Encoding` for a string that is not one they read. `base64_decode`
  takes the canonical standard-alphabet form and nothing else, so a byte string has
  one base64 spelling and a caller keying a map on the written form of a hash cannot
  hold the same hash twice. The URL-safe alphabet is refused here because it is the
  spelling of a user-friendly address, which is parsed in `ton-net`; which alphabets an
  address may be written in is undecided and is recorded beside that parser rather than
  settled here. `hex_decode` reads either case and refuses the leading `+` that
  `u8::from_str_radix` accepts.
- `BocOptions::with_stored_hashes`, which writes each cell's own hashes and
  depths ahead of its data, the form the parser has always read and checked. Off
  by default: it makes a bag larger and buys nothing to a reader that recomputes,
  this crate's parser checking each stored copy against what the cell's contents
  give and refusing a disagreement either way. A whole block uses this per-cell
  form on some of its cells, 44 of the 1428 in the two block fixtures; this writes
  it on every cell.

- `ParseOptions`, with `parse_boc_with`, `BocView::open_with` and
  `LazyBoc::open_with` beside the existing three. It carries the cell ceiling a
  parse holds a bag to, and it can only lower it: the figure is read through a
  minimum with `MAX_CELLS`, so no value of the type widens what a parse takes.
  The bound is applied where the header is read, which is the one place all
  three readers reach.

- `AugDict`, TON's `HashmapAug n X Y`, with get, set, remove and iteration. Every
  node carries a summary of the subtree below it, and a fork's is the combination
  of its two children's. What a summary means comes from the caller, through the
  new `Augmentation` trait, alongside `AugEntry` and `AugDictIter`. A summary is
  recomputed from the two children on every write rather than carried forward,
  and a write that would have to summarise a pruned branch is refused instead of
  guessed at.
- `Slice::load_u8`, `load_u16`, `load_u32` and `load_i32` read a fixed-width
  field into the type that field has, instead of returning a `u64` for the
  caller to narrow.
- `&Dict` implements `IntoIterator`.
- `Slice::load_bytes_into` and `Slice::load_snake_into` read onto the end of a
  buffer the caller owns. `load_bytes` and `load_snake` now go through them and
  are unchanged. A snake spans a chain of cells, and the returning form read each
  cell into a vector of its own before copying it into the result, where the
  destination form writes straight onto the caller's buffer. `load_bytes_into`
  checks the length before it writes anything, so a run the slice is too short to
  supply leaves the buffer as it was; a snake that fails partway along its chain
  leaves on the buffer what it had already read.
- `Builder::store_u8`, `store_u16`, `store_u32` and `store_i32` write a
  fixed-width field, the stores that answer `Slice::load_u8` and its three
  neighbours. The width is the method rather than an argument, so the pair a
  field is written and read with cannot disagree about how wide it is.
- `Slice::load_bits` reads a run of bits into a `Vec<bool>`, which is what
  `Builder::store_bits` writes. That store was the one in this crate whose output
  nothing here could read back in the form it went in. The length is checked
  before anything is read, so a slice too short leaves the cursor where it was.
- `Builder::store_int128` and `Slice::load_int128` are the signed pair beside
  `store_uint128` and `load_uint128`. Casting the unsigned reading is not the same
  thing: a field narrower than 128 bits carries its sign in the top bit of the
  field rather than the top bit of the type, so it has to be extended from there.
- `Builder::store_var_int` and `Slice::load_var_int` are the signed form of the
  length-then-bytes shape TL-B gives `VarUInteger n`. The length is the fewest
  bytes whose two's-complement form holds the value, so the sign bit is part of
  what decides it: 127 takes one byte and 128 takes two, while -128 takes one and
  -129 takes two. As with the unsigned form, the write side is minimal and the
  read side takes the length as it finds it.
- `Builder::truncate_refs` drops the references past a count, the reference half
  of `truncate_bits`. Undoing a speculative write could put the bits back and not
  the children, which left a builder having spent room it could not recover.
- `Slice::can_read` answers whether this many bits and references are still there,
  the read side of `Builder::can_extend_by`, for a decoder choosing between shapes
  before it spends anything on one.

### Changed

- `BocOptions` is `non_exhaustive` and carries a third field. A caller who
  spelled `BocOptions { index, crc32c }` writes `BocOptions::default()` with the
  new `with_index`, `with_checksum` and `with_stored_hashes` setters instead, or
  assigns the fields. The marker is what keeps a fourth option from breaking a
  caller the same way a second time.
- `apply_update` and `may_apply` rebuild through a library reference on an
  update's new side instead of refusing it. A library reference names code by
  hash and stands in for no subtree, and one sits in the state update of a
  mainnet basechain block, so refusing it refused a state transition the network
  itself produced. Something previously refused now passes, which NET-ADR-008
  section 5 calls a behavioral break. `VERIFY_EPOCH` does not move: the public
  verifier reaches a Merkle proof and a block's state update, never
  `apply_update`, and the epoch transcript is unchanged.

  A nested Merkle cell is still refused, and its message now says which case it
  refuses rather than which case it takes.

- `Dict::from_items` and `AugDict::from_items` sort their items by key once and
  build the tree from the leaves up, so each node is built with its children
  already final. Both were a loop over `set`, which rebuilds the forks it
  descended through, once per key stored. Neither signature changes, and the
  tree is the same one, held to the same mainnet root hashes it already was.
  Both now accept item sets no order of `set` builds: inserting one entry at a
  time gives the first key a label its whole width, and a value that fits beside
  the finished tree's short label need not fit beside that one. `NoRoomForBits`
  is now reported in sorted key order rather than the order items arrived in;
  `KeyLength` is still reported at the earliest offending item.
- A dictionary descent holds its edge labels inline rather than in a vector per
  level. A lookup now costs at most one allocation, the run of key bits it
  spreads the caller's key into, whatever the depth; before, it cost one for each
  label on the way down that was not empty, which on a sparse tree is one per
  level. A walk costs the key vector it hands back per entry, where it copied the
  key prefix onto the heap once per node besides. A `Dict` set and remove cost
  what rebuilding the forks they descended through costs, and no more down a
  path whose every edge carries a label than down one whose edges carry none. No
  signature changes and the trees are the ones the mainnet root hashes already
  held them to.
- `SessionCiphers::seal` returns `Result<Vec<u8>, FrameError>` and refuses a
  payload larger than one frame carries. The read side already refused a body
  outside that range, so the two ends now hold to the same ceiling. Nothing is
  sealed on a refusal and the send keystream does not move.
- `Builder::store_int` accepts a width of zero holding the value zero, which is
  what `store_uint` already did with the same argument and what `Slice::load_int`
  already read back from no bits at all. It was a `TooWide` refusal, so the one
  length a variable-length encoding reaches for its own zero failed on the signed
  side alone. A non-zero value in no bits is still refused, now as `Malformed`,
  which is the refusal the unsigned store gives it.
- `Slice::preload_uint` and `Slice::preload_bit` take `&self` rather than
  `&mut self`. They read without moving, which is what `peek_ref` beside them
  already said in its receiver; the two asked for a mutable cursor only because
  of how they saved and restored a position they never needed to move. Callers
  holding a `&mut Slice` are unaffected.

### Fixed

- `from_json`, behind the `json` feature, read a cell's hex data with
  `u8::from_str_radix`, which accepts a leading `+`. Both `+f` and `0f` answered 15
  and both are two characters, so the even-length check passed them alike and a cell
  gained a second JSON spelling for every byte below `0x10` it held. It now reads
  `hex_decode`, and the two messages a malformed `data` field reports are unchanged. Case is
  still read either way, which is a second spelling this does not close.

- `parse_boc` no longer narrows the stated cell area size before the check that
  holds a bag to it. Where `usize` is 32 bits, which is every wasm target, a bag
  could state one length, carry another, and pass that check.
- `Slice::load_var_uint` puts the cursor back when the value runs off the end of
  the slice. It read the length, failed on the value, and left the cursor inside
  the field, so a caller that recovered from the failure read part of that value
  as the next field. The primitive loads already put it back; the composite ones,
  `load_maybe_ref`, `load_dict`, `load_address` and the snake reads, still do
  not, which `tests/cell/fuzz/targets.rs` grades apart.
- `Slice::load_var_uint` refuses a length whose bit count overflows rather than
  multiplying it out. A `max` that gives a thirty-two bit length field admits a
  length past 2^29, and eight times that does not fit a `u32`: the product wrapped,
  so a hostile length read as a field of no bits, and on a build with overflow
  checks it panicked instead. It is now `CellError::TooWide`. No production caller in
  this workspace passes a `max` that large, the in-tree ones passing 7 and 16, so the
  reach is a caller this crate does not yet have.

- A bag naming one cell from two root entries reads back. A root list holds
  indices and nothing stops two of them naming the same cell, so writing such a
  bag stores the cell once and states more roots than cells, which the reader
  refused: the crate would not read a bag it had just written.

  **`VERIFY_EPOCH` rises to 2.** What is now accepted and was not: a proof whose
  root list is longer than its cell list, where every entry names a cell the bag
  carries. Nothing is now refused that was accepted before, and no proof, hash,
  signature or freshness rule moved. A caller that stored a verified result under
  epoch 1 can keep it; the widened set only admits encodings epoch 1 turned away,
  and each is checked exactly as before once it is read.

  The root list is still bounded twice: by the cell ceiling a parse runs under,
  and by the bytes the bag carries for it, so a small bag naming a large root
  count is refused rather than reserved for.

## [0.3.0] - 2026-07-22

### Added

- **Block sync.** A client walks from the key block the network configuration
  pins to the current masterchain head, checking a two-thirds validator signature
  set at every link, and reads an account proved against the block it arrived at.
  A read is now trust-minimized end to end: nothing is trusted but the pinned
  block and the local clock.
- `Client::sync` walks the chain forward and reports what it cost.
- `Client::connect_from` resumes from a key block proven on an earlier run, which
  turns a first walk of over a thousand links into a single one. `Client::anchor`
  returns the block to save.
- `Client::account` returns `Verified<Account>`, a type that cannot be
  constructed outside the crate without a proof having checked out. The proved
  read is the one a caller lands on without choosing; `Client::account_reported`
  is the unchecked exception, and it returns a different type.
- `ton_net::verify_account` and `BlockIdExt::new`, so a caller can verify a read
  and name an out-of-band anchor without going through the facade.
- The Node binding carries an anchor in both directions and exposes `account`,
  `accountAt`, `accountReported`, `accountState` and `verifyAccount`.
- Validator signature checking in both of the forms mainnet uses, including the
  Simplex vote, whose candidate hash is now bound to the block a link claims.
- `AdnlError::NoRandomness`. An operating system that will not supply randomness
  used to end the calling process; it now fails the call that needed it.
- `VERIFY_EPOCH`, and `verifyEpoch()` in the Node binding. A version says whether
  the API changed; it cannot say whether an upgrade changed what the library
  accepts as proven, because that boundary moves independently of any signature.
  This number answers the second question and rises only when the boundary does,
  so a caller who stored the epoch a result was verified under can decide whether
  to check it again. It starts at 1, and each rise is recorded here as the delta
  in what is accepted and what is refused. The boundary itself is pinned as a
  transcript in `crates/ton-net/tests/epoch.rs`, so a change to what verifies
  fails the build rather than passing unnoticed.
- `ErrorCode` and `Error::code`, the stable name for a kind of failure. Which
  failure occurred decides what a caller does next, and two of the answers are
  opposites: a transport failure means the socket dropped and the server may be
  fine, a proof failure means the server did not prove its answer and asking it
  again is the reverse of what this library is for. The names were already a
  documented contract in the Node binding's message prefix and are unchanged;
  they now come from the core, so a binding maps rather than invents.
- Property tests over the cell codec: the bag-of-cells round trip preserves a
  cell's representation hash and its bytes, a parsed cell hashes to what its
  own parts imply, arbitrary and truncated input is refused rather than fatal,
  and a cell has exactly one accepted encoding.
- `docs/security/threat-model.md`, which works out what an attacker controls at
  each of the four boundaries, which check refuses it, and what is left trusted.

### Fixed

Three of these are soundness failures in proof verification. They were found and
fixed before any version reached a registry, so no published release ever carried
them.

- **A proof could deny that an account exists.** A pruned account dictionary and
  an empty one both begin with a clear bit, so a server could withhold the
  dictionary and have the answer read as a proved absence. The two are now
  distinguished, and a withheld answer is refused.
- **A proof could hide what it answered for.** The root check tested for an exotic
  cell but not for a level mask, and a level-1 pruned branch answers for the hash
  it replaced, so a substituted account body verified against the block. The mask
  is now checked.
- **An exotic cell was not held to its own shape.** A pruned branch could carry
  references, and a cell could claim more references than the model allows. Both
  are refused, along with a pruned branch whose length disagrees with its level
  mask.
- A byte-aligned cell had two encodings, one of which produced a hash no other
  implementation computes.
- A degenerate key exchange is refused. A low-order server key decompresses fine
  but drives the shared secret to zero, which would have made the session
  readable.
- A connection whose read was cancelled mid-frame is marked broken rather than
  reused. The stream cipher had already advanced, so every later frame would have
  decrypted to noise.
- A sync that a server calls complete is checked against the block it was asked
  to reach, rather than believed.
- A sync is bounded by elapsed time as well as by rounds, and a local clock behind
  the chain is reported instead of quietly passing.
- The maximum frame size matches the protocol rather than sitting below it.
- An address carries its tag rather than assuming one, and base64 input is
  required to be canonical.
- Error kinds report where a failure came from, so a decode failure inside a proof
  no longer arrives as something softer than a proof failure.
- A thrown error in the Node binding carries a stable code prefix a caller can
  branch on.
- `Slice::load_bytes` refuses a byte count whose bit count overflows a `usize`.
  The multiplication wrapped, the length check passed on the wrapped value, and
  the allocation that followed was made against the count as given.
- The third-party notices shipped in every npm tarball are checked against the
  dependency graph rather than regenerated by hand and assumed current. An npm
  version can be deprecated but never replaced, so notices that no longer
  describe what ships cannot be corrected after a publish.
- The TOML files follow the indentation `.editorconfig` declares for them. It
  had asked for two spaces since it was written and all nineteen files used
  four, so the convention the repository published and the one it followed were
  different. `taplo` decides now, and CI checks.
- Two spellings of `unparsable`, found by adding a spell check rather than by
  reading.
- The readme's sync measurement. It carried a download size no test measures
  and a link count from the walk before last. The binding readme had already
  been corrected and this one had not, so the two disagreed.
- The Node binding's two musl binaries are built on musl. Both had been built on
  the glibc runner: the x64 one linked against glibc and needed
  `ld-linux-x86-64.so.2`, which no musl system carries, and the arm64 one did not
  link at all. They are built inside Alpine now, and each one is loaded on a
  runner of its own architecture rather than assumed to work.

### Changed

- A cold sync got about a third faster by stopping once the signature weight
  passes the threshold, rather than verifying the rest of an honest set.
- The bound on cell count is set by what a cell costs in memory rather than by
  what the format permits.
- Every library crate refuses to panic on input. `unwrap`, `expect`, `panic`,
  `unreachable`, `todo` and slice indexing are denied in each of them, so a
  decoder handed bytes it cannot read returns an error rather than unwinding
  through whatever embedded it. The exceptions are named in the source with the
  argument for why the case cannot arise.

### Security

The three soundness failures above compose. A liteserver that exploited all of
them could deny an account exists, replace a contract's code and data with
placeholders, and fill those placeholders with cells of its own, and the result
would have been handed to a caller as verified. Each now has a regression test,
and each test was confirmed to fail with its guard removed.

## [0.2.0] - 2026-07-21

The cell and proof engine.

### Added

- The TON cell model: representation hashing, level masks, exotic cells, and the
  bag-of-cells codec in both directions.
- The TL-B for TON's block and account structures, decoded from cells.
- Merkle proof verification, and `verify_account` for a read checked against a
  masterchain block hash the caller supplies.
- `Verified<T>`, which names the anchor a value was proved against.
- A Node binding for the verified read.

## [0.1.0] - 2026-07-21

The foundation: a liteserver read over TON's own protocols, from Node.

### Added

- A TL codec over `tl-proto` with CRC32-IEEE constructor tags.
- ADNL over TCP: the handshake, session key derivation, and encrypted stream
  framing, sans-I/O over a transport seam.
- The liteserver query layer, and the network configuration loader.
- A napi-rs Node binding.

Reads at this version are the server's unproven word, and are marked in the API
with a `ServerReported` type.

[Unreleased]: https://github.com/nirapod-labs/ton-net/compare/v0.4.0...HEAD
[0.4.0]: https://github.com/nirapod-labs/ton-net/compare/v0.3.0...v0.4.0
[0.3.0]: https://github.com/nirapod-labs/ton-net/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/nirapod-labs/ton-net/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/nirapod-labs/ton-net/releases/tag/v0.1.0
