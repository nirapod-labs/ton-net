# ton-net

A direct TON network client for Node. It speaks ADNL over TCP to a liteserver and
verifies what comes back, so a balance is checked against a block the client
walked to itself rather than taken on a server's word. No HTTP indexer in the
path.

The core is Rust; this package is a prebuilt native binding, so installing it
needs no compiler and no toolchain.

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

// The elector, which every TON network has and which is always active.
const account = await client.account(
  "-1:3333333333333333333333333333333333333333333333333333333333333333",
);

console.log(account.value.balance, account.value.status);
console.log("proved against block", account.anchor.seqno);
```

A proved read comes back as `{ value, anchor }`: the account, and the block it
was proved against. The two stay together because a balance means nothing
without the block it was true at. A read that fails verification throws rather
than returning something unverified.

Balances and logical times are decimal strings, not numbers. Mainnet balances
run past what a JavaScript number holds exactly, so a number would round some of
them silently.

`account()` walks on every call. Reading several accounts at one moment is
`sync()` once and then `accountAt` with the head it returned, rather than a walk
apiece; the next section is how not to pay for the first walk twice either.

Runnable versions of this and the next section are in [`examples/`].

## Paying for the walk once

A first sync walks every key block published since the pinned one. Measured
against mainnet on 2026-07-22, that was 1246 links over 78 replies in 118
seconds; read it as a scale rather than a constant, since the link count climbs
with the chain. Saving the block it ended on turned the next run into one link in
under two seconds.

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

`anchor()` returns null before the first sync. A `BlockId` carries its two hashes
as Buffers, and `JSON.stringify` turns those into `{ type, data }` objects rather
than Buffers, so persisting one takes a conversion in each direction;
[`examples/resume.mjs`] does both. The shard is a string for the opposite reason:
it is 64 bits, which a JavaScript number cannot hold exactly, and as a string it
stores and compares unchanged.

## Proved and reported are different shapes

The API keeps the two apart so they cannot be confused at a call site.

| method | returns | means |
|---|---|---|
| `account(address)` | `{ value, anchor }` | checked against a block this client proved |
| `accountAt(address, trusted)` | `{ value, anchor }` | checked against a block the caller supplies |
| `accountReported(address)` | `{ value, proof }` | the decoded account the server claims, unchecked |
| `accountState(address, block)` | `{ value, proof }` | the raw state and proof bytes, unchecked |
| `masterchainInfo()` | `{ value, proof }` | the server's own claim about the head |

Passing `masterchainInfo()` to `accountAt` on the same client proves nothing: it
only shows the server agrees with itself. The blocks worth supplying are one this
client proved, from `sync()` or `anchor()`, and one the caller trusts
independently.

## Checking a read later

`verifyAccount` is the check on its own, for bytes and an anchor that arrive
separately. It reaches no network, so the same bytes always give the same answer.

It takes the raw state, which is what `accountState` returns and what
`accountReported` does not: the reported form is already decoded, and the bytes a
proof is checked against are gone by then.

```js
import { verifyAccount } from "ton-net";

// Read now, at whichever block, checking nothing.
const block = (await client.masterchainInfo()).value;
const state = await client.accountState(address, block);

// Check whenever that block turns out to be worth something, which is the point
// of the split: the bytes and the reason to trust them can arrive apart.
const account = verifyAccount({
  address,
  trustedRootHash: block.rootHash,
  proof: state.proof,
  state: state.value.state,
  // shardProof: state.value.shardProof, outside the masterchain
});
```

The proofs root at that one block, so `trustedRootHash` is its hash and no other.
What can arrive later is the standing to believe the block, not a different one.

## Errors

A thrown error's message begins with a stable code, so a caller can branch on the
kind without matching prose:

```js
const code = (error) => String(error.message).split(":", 1)[0];
```

The distinction that matters is whether another server is the right answer. A
client that retries a server which failed to prove its answer is doing the
opposite of what this library is for.

| code | meaning |
|---|---|
| `PROOF` | the answer was not what the block says |
| `CELL` | the bytes did not decode as cells |
| `DECODE` | the reply did not decode |
| `SYNC` | the chain of key blocks did not connect |
| `STALE` | the proven head is older than `maxHeadAge` allows |
| `CLOCK_BEHIND` | the local clock is too far behind to judge freshness |
| `TRANSPORT` | the connection failed |
| `CONNECTION_LOST` | the connection dropped mid-call |
| `TIMEOUT` | the server did not answer in time |
| `HANDSHAKE` | the ADNL handshake failed |
| `LITESERVER` | the server returned an error of its own |
| `CONFIG` | the network configuration could not be used |
| `ADDRESS` | the address did not parse |
| `INVALID_ARGUMENT` | an argument was not usable |

The first four are this server's answer being wrong, and neither asking it again
nor asking elsewhere makes an unprovable answer provable: something is broken.
`STALE` is a server that is genuinely behind or replaying, where another server is
the right move and a retry of this one is not. `CLOCK_BEHIND` is neither, and the
remedy is a correct clock. The next five are the connection rather than the
answer, so another server, or the same one again, may be fine. The last three are
the caller's own input.

The code is in the message rather than in `error.code`, which would be the natural
place, because napi pins the status of anything returned from an async function to
its own enum and almost every call here is async. `error.code` is that napi status
throughout, not one of these.

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
  from last year passes every other check. `config.withMaxHeadAge(seconds)`
  returns a config with a tighter bound, and a head past it raises `STALE`.

## License

Apache-2.0. Copyright 2026 Nirapod Labs; maintained by athexweb3.

Source, design records and issues:
[github.com/nirapod-labs/ton-net](https://github.com/nirapod-labs/ton-net).

[`examples/`]: https://github.com/nirapod-labs/ton-net/tree/main/bindings/node/examples
[`examples/resume.mjs`]: https://github.com/nirapod-labs/ton-net/blob/main/bindings/node/examples/resume.mjs
