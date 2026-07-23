# ton-net

A direct client for the TON network, in Rust. It speaks TON's own wire protocols,
TL over ADNL over TCP, and verifies what a liteserver returns against validator
signatures rather than trusting the server that sent them. No HTTP indexer sits in
the path.

This crate is the facade over the layered core. It composes the crates beneath it:
`ton-net-tl` (the TL codec), `ton-net-cell` (the cell model and bag-of-cells codec),
`ton-net-block` (the block and account structures and the proof engine),
`ton-net-adnl` (ADNL over TCP), and `ton-net-lite` (the liteserver query layer). A
consumer depends on `ton-net` and reaches the read path through one type.

## What it does

A `Client` owns one ADNL channel to one liteserver. Over it, the crate does three
things:

- **Connect.** `Client::connect` tries the configured liteservers in turn until one
  completes the handshake.
- **Sync.** `Client::sync` walks from the key block the configuration pins to the
  network's current head, checking a two-thirds validator signature set at every
  link, and ends holding a block it proved rather than one a server named.
- **Read a proven account.** `Client::account` reads an account and binds it, by
  Merkle proof, to a block the client established itself.

Two inputs stay trusted, and both are named: the block the configuration pins, since
a walk has to start somewhere, and the local clock. A proof establishes that a block
is real and was committed, not when it was served, so a proven head older than a
configured bound is refused rather than obeyed.

## The trust guarantee

A read says in its type whether it was proved. `Client::account` returns
`Verified<Account>`; `Client::account_reported` returns `ServerReported<Account>`.
The two are different types, and no operation turns the first into the second.

`Verified<T>` has no public constructor. A value of the type exists only where this
crate checked the proofs, so it cannot be forged by a caller and cannot be built from
a server's unchecked word. Its claim is relative: the value is as trustworthy as the
block it was proved against, and no more.

The plain method name is the proven one. `account` proves; `account_reported` is the
unchecked exception, named for what it is. A caller lands on the safe read without
choosing it, and takes the server's word on purpose.

`VERIFY_EPOCH` is a separate integer, 1 today. A version says whether the API
changed; it cannot say whether an upgrade changed what the library accepts as proven,
because that boundary moves independently of any signature. This number rises only
when the accept and reject boundary moves, so a caller that stored the epoch a result
was verified under can decide whether to verify it again.

## Usage

```rust,no_run
use ton_net::{Address, Client, Config};

# async fn run() -> Result<(), ton_net::Error> {
let config = Config::mainnet();
let mut client = Client::connect(&config).await?;

// The elector, a system contract that is always active.
let elector = Address::parse(
    "-1:3333333333333333333333333333333333333333333333333333333333333333",
)?;

// Proved against a block the client walked to itself, from the pinned key block,
// one validator signature set at a time.
let account = client.account(&elector).await?;
println!("proved balance: {}", account.value().balance);

// The server's word, for a caller who asks for it by name.
let reported = client.account_reported(&elector).await?;
println!("reported balance: {}", reported.value().balance);
# Ok(())
# }
```

The first `account` call pays for the full walk. Saving `client.anchor()` and handing
it to `Client::connect_from` on a later run turns that walk into a single link. A
caller reading many accounts against one proved head can `sync` once and pass the head
to `Client::account_at` rather than walk on every read.

## What ships today, and what is ahead

Version 0.3.0 is a trust-minimized read path, end to end: connect, sync, and read a
proven account, with nothing trusted but the pinned block and the local clock.
Working today are the TL codec, ADNL over TCP, the liteserver reads, the cell and
proof engine, key-block sync, and a Node binding.

The rest is committed scope, not yet built. Among the larger pieces: the write path
and wallets, the DHT, RLDP, and the local TVM. The order they arrive in is
dependency-first, which places the write path early and the TVM last. The scope
boundary is fixed in [NET-ADR-003]: the whole of what a program talking to TON
speaks, and never what a node or a validator does. The [roadmap] records the
sequence.

## Documentation

- [Roadmap][roadmap]: the release sequence from here to v1.0.0.
- [NET-ADR-003]: the client scope and the write path.
- [Threat model]: what an attacker controls at each boundary, which check refuses it,
  and what is left trusted.
- [Changelog]: the per-release record, including each move of the verification epoch.

## License

Apache-2.0. Copyright 2026 Nirapod Labs; maintained by athexweb3.

[NET-ADR-003]: https://github.com/nirapod-labs/ton-net/blob/main/docs/adr/NET-ADR-003-scope-and-write-path.md
[roadmap]: https://github.com/nirapod-labs/ton-net/blob/main/docs/roadmap.md
[Threat model]: https://github.com/nirapod-labs/ton-net/blob/main/docs/security/threat-model.md
[Changelog]: https://github.com/nirapod-labs/ton-net/blob/main/CHANGELOG.md
