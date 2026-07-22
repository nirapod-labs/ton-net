# ton-net

A direct TON network client for Node. It speaks ADNL over TCP to a liteserver and
verifies what comes back, so a balance is checked against a block the client
walked to itself rather than taken on a server's word. No HTTP indexer in the
path.

The core is Rust; this package is a prebuilt native binding, so installing it
needs no compiler and no toolchain.

> Not published yet. The first registry release is v0.3.0, the version where a
> read stops depending on any hash the caller has to supply. Until then the
> package is built from the repository.

## Install

```sh
npm install ton-net
```

The binary for the current platform arrives as an optional dependency. Prebuilt
for macOS and Linux on x64 and arm64, including musl, and for Windows on x64.

Needs Node 18.17 or newer.

## Reading an account

```js
import { Config, TonClient } from "ton-net";

const client = await TonClient.connect(Config.mainnet());

// Walks from the key block the config pins to the network's current head,
// checking a validator signature set at every link.
await client.sync();

const account = await client.account("EQC...");
console.log(account.balance, account.status);
```

`account()` returns only what the walk proved. A read that fails verification
throws rather than returning something unverified.

## Paying for the walk once

A first sync walks every key block published since the pinned one. Measured
against mainnet on 2026-07-22, that was 1246 links over 78 replies and a little
over two minutes; read it as a scale rather than a constant, since the link count
climbs with the chain. Saving the block it ended on turns the next run into a
single link, in about a second.

```js
const client = await TonClient.connect(Config.mainnet());
await client.sync();
const anchor = await client.anchor();
// persist `anchor`

// next process
const resumed = await TonClient.connectFrom(Config.mainnet(), anchor);
await resumed.sync();
```

The anchor is the client's root of trust: everything it goes on to believe is
derived from that block. It is worth exactly what the storage it came from is
worth, so anything that can write there can choose what the client trusts.

## Verified and reported are different types

The API keeps the two apart so they cannot be confused at a call site.

| method | returns | means |
|---|---|---|
| `account(address)` | `VerifiedAccount` | checked against a block this client proved |
| `accountAt(address, block)` | `VerifiedAccount` | checked against a block the caller supplies |
| `accountReported(address)` | `ReportedAccount` | what the server said, with its proof, unchecked |
| `masterchainInfo()` | `ReportedMasterchainInfo` | the server's own claim about the head |

Anything named `Reported` carries the proof bytes so a caller can check it later,
and `verifyAccount()` is the function that does so.

## Errors

A thrown error's message begins with a stable code, so a caller can branch on the
kind without matching prose:

| prefix | meaning |
|---|---|
| `PROOF:` | verification failed; the answer was not what the block says |
| `TRANSPORT:` | the connection failed or was lost |
| `LITESERVER:` | the server returned an error |
| `CONFIG:` | the network configuration could not be used |
| `INVALID:` | an argument was not usable |

The code is in the message rather than in `error.code` because the async
boundary in this binding pins the error type to Node's own status enum.

## Knowing when the rules changed

`verifyEpoch()` returns an integer that rises whenever the set of things this
library accepts as proven changes. The package version cannot answer that, because
the accept and reject boundary moves independently of any signature.

```js
import { verifyEpoch } from "ton-net";

if (cached.epoch < verifyEpoch()) {
  // this build accepts a different set of things; verify again
}
```

## What is still taken on trust

Two things, and they are the whole list:

- **The block the config pins.** A walk has to start somewhere. Pass an anchor to
  `connectFrom` to supply that block instead.
- **The local clock.** A proof says a block is real and was committed. It says
  nothing about when it was handed over, so a server replaying a genuine chain
  from last year passes every other check. `Config.withMaxHeadAge` sets how much
  age is tolerated.

## License

Apache-2.0. Copyright 2026 Nirapod Labs; maintained by athexweb3.

Source, design records and issues:
[github.com/nirapod-labs/ton-net](https://github.com/nirapod-labs/ton-net).
