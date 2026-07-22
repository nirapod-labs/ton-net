# ton-net

A direct TON network client. It speaks TON's own protocols, TL over ADNL over TCP,
and verifies what a liteserver returns against a block it walked to itself, so a
balance is proven rather than taken on the server's word. No HTTP indexer in the
path.

This crate is the entry point. It composes the layers below it: [`ton-net-tl`],
[`ton-net-cell`], [`ton-net-block`], [`ton-net-adnl`] and [`ton-net-lite`].

**It is early.** Reading a proved account works and is tested against mainnet.
Sending a transaction, wallets, the DHT and local contract execution do not exist
yet. The [roadmap] is the order the rest arrives in.

## Reading an account

```rust,no_run
use ton_net::{Address, Client, Config};

# async fn read() -> Result<(), ton_net::Error> {
let config = Config::mainnet();
let mut client = Client::connect(&config).await?;

// The elector, a system contract that is always active.
let address = Address::parse(
    "-1:3333333333333333333333333333333333333333333333333333333333333333",
)?;

// Walks from the key block the config pins to the network's current head,
// checking a validator signature set at every link, then proves the account
// against the block it arrived at.
let account = client.account(&address).await?;
println!("{}", account.value().balance);
# Ok(())
# }
```

`account` returns a `Verified<Account>`, a type with a private constructor that
cannot be built outside this crate without a proof having checked out. A read that
fails verification is an error, never a value. `account_reported` is the same read
with nothing checked, and it returns a different type, so the two cannot be
confused.

## Paying for the walk once

The first walk covers every key block published since the pinned one. Against
mainnet in July 2026 that was 1246 links over 78 replies and a little over two
minutes. Saving the block it ended on turns the next run into a single link.

```rust,no_run
use ton_net::{BlockIdExt, Client, Config};

# fn save(client: &Client) -> Option<BlockIdExt> {
// After a sync, this is the key block the client proved and now trusts.
client.anchor().cloned()
# }

# async fn resume(saved: &BlockIdExt) -> Result<(), ton_net::Error> {
let config = Config::mainnet();
let mut client = Client::connect_from(&config, saved).await?;
client.sync().await?;
# Ok(())
# }
```

That anchor is the client's root of trust. Everything derived from it is worth
exactly what the storage it came from is worth: whatever can write to where it is
kept can choose what this client believes.

## What is still taken on trust

Two things, and they are the whole list:

- **The block the config pins.** A walk has to start somewhere. Passing an anchor
  to `connect_from` supplies that block instead.
- **The local clock.** A proof establishes that a block is real and was committed
  by the validators, and says nothing about when it was handed over. A server
  replaying a genuine chain from last year passes every other check.
  `Config::with_max_head_age` sets how much age is tolerated, and a clock far
  enough behind is reported rather than quietly passed.

## Knowing when the rules changed

`VERIFY_EPOCH` is an integer that rises whenever the set of things this library
accepts as proven changes. The crate version cannot answer that, because the
accept and reject boundary moves independently of any signature. Storing it beside
a result makes an upgrade answerable:

```rust
# let cached_epoch = 0u32;
if cached_epoch < ton_net::VERIFY_EPOCH {
    // this build accepts a different set of things; verify again
}
```

## Scope

Working today: the TL codec, ADNL over TCP, liteserver reads, cell and proof
verification, and key-block sync. Everything else, including the write path, the
DHT, RLDP and a local TVM, is ahead. See the [roadmap] and [NET-ADR-008].

## License

Apache-2.0. Copyright 2026 Nirapod Labs; maintained by athexweb3.

[`ton-net-tl`]: https://crates.io/crates/ton-net-tl
[`ton-net-cell`]: https://crates.io/crates/ton-net-cell
[`ton-net-block`]: https://crates.io/crates/ton-net-block
[`ton-net-adnl`]: https://crates.io/crates/ton-net-adnl
[`ton-net-lite`]: https://crates.io/crates/ton-net-lite
[roadmap]: https://github.com/nirapod-labs/ton-net/blob/main/docs/roadmap.md
[NET-ADR-008]: https://github.com/nirapod-labs/ton-net/blob/main/docs/adr/NET-ADR-008-scope-and-write-path.md
