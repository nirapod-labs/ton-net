# ton-net

A direct TON network client. It speaks TON's own protocols, TL over ADNL over TCP,
and verifies what a liteserver returns against a block it walked to itself, so a
balance is proven rather than taken on the server's word. No HTTP indexer in the
path.

This crate is the entry point. It composes the layers below it: [`ton-net-tl`],
[`ton-net-cell`], [`ton-net-block`], [`ton-net-adnl`] and [`ton-net-lite`].

## Reading an account

```rust,no_run
use ton_net::{Client, Config};

# async fn read() -> Result<(), ton_net::Error> {
let mut client = Client::connect(Config::mainnet()).await?;

// Walks from the key block the config pins to the network's current head,
// checking a validator signature set at every link.
client.sync().await?;

let account = client.account_verified("EQC...").await?;
println!("{}", account.value().balance);
# Ok(())
# }
```

`account_verified` returns a `Verified<Account>`, a type that cannot be built
outside this crate without a proof having checked out. A read that fails
verification is an error, never a value.

## Paying for the walk once

A first sync walks every key block published since the pinned one. Against mainnet
in July 2026 that was 1244 links over 78 replies, about 52 MB and a minute and a
half. Saving the block it ended on turns the next run into a single link.

```rust,no_run
# use ton_net::{Client, Config};
# async fn resume(saved: ton_net::BlockIdExt) -> Result<(), ton_net::Error> {
let mut client = Client::connect_from(Config::mainnet(), saved).await?;
client.sync().await?;
# Ok(())
# }
```

That anchor is the client's root of trust. Everything derived from it is worth
exactly what the storage it came from is worth.

## What is still taken on trust

Two things, and they are the whole list:

- **The block the config pins.** A walk has to start somewhere. Pass an anchor to
  `connect_from` to supply that block instead.
- **The local clock.** A proof establishes that a block is real and was committed
  by the validators, and says nothing about when it was handed over. A server
  replaying a genuine chain from last year passes every other check.
  `Config::with_max_head_age` sets how much age is tolerated, and a clock far
  enough behind is reported rather than quietly passed.

## Scope

Working today: the TL codec, ADNL over TCP, liteserver reads, cell and proof
verification, and key-block sync. ADNL over UDP, the DHT, and a local TVM are the
milestones ahead. See the [roadmap] and [NET-ADR-002] for what is deliberately out
of scope.

## License

Apache-2.0. Copyright 2026 Nirapod Labs; maintained by athexweb3.

[`ton-net-tl`]: https://crates.io/crates/ton-net-tl
[`ton-net-cell`]: https://crates.io/crates/ton-net-cell
[`ton-net-block`]: https://crates.io/crates/ton-net-block
[`ton-net-adnl`]: https://crates.io/crates/ton-net-adnl
[`ton-net-lite`]: https://crates.io/crates/ton-net-lite
[roadmap]: https://github.com/nirapod-labs/ton-net/blob/main/docs/roadmap.md
[NET-ADR-002]: https://github.com/nirapod-labs/ton-net/blob/main/docs/adr/NET-ADR-002-scope.md
