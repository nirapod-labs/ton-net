# ADNL liteserver handshake spike

A standalone program that completes an ADNL-over-TCP handshake with a TON mainnet
liteserver and issues a single `liteServer.getMasterchainInfo` query, building
every byte directly rather than through an ADNL library.

It checks the client's lowest layer against a live server: the TL constructor
tags, the x25519 handshake and key derivation, the AES-256-CTR stream framing,
and the liteserver query wrapper. The crate lines match
[NET-ADR-003](../../docs/adr/NET-ADR-003-dependencies.md); the wire layout
follows [docs/protocol/wire-format.md](../../docs/protocol/wire-format.md).

## Run

```
cargo run --release
```

The program tries a snapshot of public mainnet liteservers in turn and stops at
the first that answers. It needs outbound TCP to the liteserver ports in the
snapshot.

## What it checks

- The five TL constructor ids (`pub.ed25519`, `adnl.message.query`,
  `adnl.message.answer`, `liteServer.query`, `liteServer.getMasterchainInfo`),
  each computed as crc32 of its canonical combinator string and cross-checked in
  wire form against the `ton_api.tl` and `lite_api.tl` schema magics.
- The 256-byte handshake: the server key id, the ephemeral client key, the ECDH
  shared secret over the ed25519-to-montgomery converted server key, and the
  AES-256-CTR handshake cipher over the 160-byte session parameters.
- The stream frame in both directions under the continuous send and receive
  ciphers: length prefix, nonce, payload, and the sha256 checksum.
- The query wrapper: `adnl.message.query` around `liteServer.query` around the
  method, with TL byte-string framing and padding.

A run succeeds when the server returns a checksum-valid frame that echoes the
request query id and decodes to `liteServer.masterchainInfo`, from which the
program reads the masterchain block id and prints the seqno.

## Observed

Against `5.9.10.47:19949`, all five constructor ids match their schema magics,
the handshake completes, and the server returns a `liteServer.masterchainInfo`
for the masterchain (workchain -1, shard `0x8000000000000000`) at a current
seqno. The read path round-trips over an encrypted, checksum-verified ADNL frame.

## Not covered

The spike stops at an unverified read. It does not parse the cell/BoC layer,
verify Merkle proofs, check validator signatures, or run TVM get-methods; those
layers are tracked in [docs/roadmap.md](../../docs/roadmap.md). It uses blocking
sockets and a hardcoded server snapshot to stay self-contained.
