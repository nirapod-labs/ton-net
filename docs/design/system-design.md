---
title: ton-net system design
status: draft
date: 2026-07-20
adrs: NET-ADR-001, NET-ADR-002, NET-ADR-003, NET-ADR-004, NET-ADR-005
---

# ton-net system design

## Scope

Covers the full client stack: the Rust core (TL codec, ADNL transport over TCP
and UDP, DHT, liteserver queries, proof engine, block-sync, TVM, config), the
transport seam, and the binding boundary each language crosses. Does not cover
the node-only protocols (RLDP, overlays, catchain, TON Storage, TON Sites), which
are out of scope per NET-ADR-002.

## Components

Bottom to top. Each has one responsibility and a boundary it does not cross.

- **Crypto primitives**: x25519 ECDH, ed25519 sign and verify, sha256, AES-256-CTR,
  and the ed25519-to-x25519 Montgomery conversion ADNL needs. Thin wrappers over
  the pinned RustCrypto and dalek crates (NET-ADR-003). Knows nothing protocol-
  specific.

- **TL codec**: TON's Type Language wire format via `tl-proto`: CRC32-IEEE
  constructor tags, boxed and bare types, `bytes`, `vector`, `int256`, flags.
  Fed the official `ton_api.tl` and `lite_api.tl` schemas. Bytes to and from typed
  values; knows nothing of transport.

- **Transport (trait)**: the seam. Two shapes: a datagram interface (send/recv to
  a peer, for ADNL-UDP and DHT) and a stream interface (for ADNL-TCP to a
  liteserver). Implementations: `UdpTransport` and `TcpTransport` on native
  (tokio), `WsTransport` on the browser (WebSocket, stream only). The core calls
  the trait; it never opens a socket itself.

- **ADNL channel**: the encrypted transport. TCP variant: the 256-byte handshake,
  the s1/s2/v1/v2 session-key split, the length-nonce-payload-checksum stream
  frame. UDP variant: packet encryption to a peer public key, channel
  establishment, `adnl.packetContents` with seqno and confirm_seqno. Owns
  encryption and sequence state; calls a transport to move bytes. Wire detail in
  [protocol/wire-format.md](../protocol/wire-format.md).

- **DHT client**: Kademlia over ADNL-UDP (k=10, a=3). Derives a DHT key-id,
  runs an iterative `findValue` or `findNode`, verifies the signature on a returned
  value, decodes the payload. Read (`findValue`, `findNode`, `getSignedAddressList`)
  and write (`store` a signed address record). Composes ADNL channels and the TL
  codec; does not know why a caller wants a value.

- **Liteserver client**: wraps a `liteServer.*` method as
  `adnl.message.query` over `liteServer.query`, sends it over an ADNL-TCP channel,
  decodes the response. The full client method set (account state, transactions,
  config, blocks, block proofs, `runSmcMethod`, `sendMessage`). Returns raw
  responses plus their proof blobs; does not itself verify.

- **Cell / BoC engine**: TON's cell model: ordinary and exotic cells (pruned
  branch, Merkle proof, Merkle update), representation hashing with level masks,
  BoC parse and serialize. The substrate the proof engine stands on.

- **Proof engine**: the trust-minimization core. The TL-B for Block, ShardState,
  ShardAccounts, Account, Transaction and ConfigParams, and the five `check_*_proof`
  routines: verify a Merkle proof's virtual-root hash equals a trusted hash, then
  read the un-pruned cells as trusted. Turns a liteserver response plus a trusted
  block hash into a verified value.

- **Block-sync engine**: establishes the trusted block hash. A pinned init
  key-block anchor, `getBlockProof` link-walking (forward links across key-block
  boundaries, backward links into proven state), validator-set derivation from
  config params 28 and 34, and the two-thirds Ed25519 signature check over
  `ton.blockId`. Output: the current masterchain block hash, trusted.

- **TVM**: runs a get-method locally over proven code, data and config (NET-ADR-005).
  Consumes only proven inputs; produces a trust-minimized result distinct from a
  raw `runSmcMethod` response.

- **Config loader**: `global-config.json` to a typed list of liteservers, DHT
  seed nodes, and the init block. Public data; no secret.

- **Binding shims**: napi-rs, wasm-bindgen, UniFFI, flutter_rust_bridge, pyo3.
  Marshalling only, zero behavior (NET-ADR-004).

## Contracts

The surface each binding exposes, language-neutral. Errors are a closed set.

```
Config.loadMainnet() / loadFromUrl(url) -> Config
    errors: NetworkError, ParseError

Client.connect(config, transport) -> Client         // opens a liteserver channel
Client.getAccount(address) -> VerifiedAccount        // proof-verified
    errors: NotFound, BadProof, Timeout, TransportError
Client.runGetMethod(address, method, args) -> TvmResult   // local TVM, trust-minimized
Client.sendMessage(bocBytes) -> SendStatus           // unprovable by construction
Client.getConfig(params) -> VerifiedConfig
Client.getTransactions(address, from) -> [VerifiedTransaction]

Dht.open(config, udpTransport) -> Dht
Dht.resolveAddress(adnl: bytes32) -> AddressList     // signature-verified
Dht.findValue(key) -> Value
Dht.store(record)                                    // write a signed record

Sync.anchor(initKeyBlock)                            // the one trust assumption, explicit
Sync.currentMasterchain() -> TrustedBlockId

Transport (trait, host- or core-provided per target):
    stream:  connect(peer) -> Channel; Channel.send/recv(bytes)
    datagram: send(peer, bytes); recv() -> (peer, bytes)
```

Invariants the contract carries:

- `getAccount` never returns state whose proof did not verify against a
  block trusted through `Sync`. `BadProof` instead.
- `runGetMethod` returns a `TvmResult` executed locally over proven inputs; a raw
  server `runSmcMethod` value is a different, explicitly server-trusted type.
- `resolveAddress` never returns an address whose DHT record signature did not
  verify against the requested key.
- No method accepts, returns, or logs a user wallet key. The type surface has no
  place for one.
- TL decode of any byte sequence terminates and yields a typed value or a
  `ParseError`; it never panics or over-allocates.
- Every call is bounded in time; absent a response within the deadline, `Timeout`.

## Data flow

The proof-verified account read, the headline path:

```
Client.getAccount(address)
  -> Sync.currentMasterchain() gives a trusted MC block id (see below)
  -> Liteserver: getAccountState(mc_block, address)
  <- accountState{ shard_proof, proof, state }
  -> Cell engine: parse the three BoCs
  -> Proof: check_shard_proof   (mc-block Merkle proof root == trusted mc hash)
                                -> trusted shard-block id from shard_hashes
  -> Proof: check_account_proof (shard-block proof root == trusted shard hash)
                                -> trusted account-state hash
  -> assert representation_hash(state) == trusted account-state hash
  -> deserialize with the account TL-B  -> VerifiedAccount
  any mismatch -> BadProof
```

Establishing the trusted masterchain hash (`Sync`), done once and refreshed:

```
Sync.anchor(pinned init key-block)                  // out-of-band trust assumption
  -> Liteserver: getMasterchainInfo -> UNTRUSTED candidate head
  -> Liteserver: getBlockProof(known = anchor, target = head)
  <- partialBlockProof steps
  for each step:
    blockLinkForward: check_block_header_proof(dest_proof, to.hash)
                      derive validator set from `from` key-block (config 28/34)
                      check_block_signatures: Ed25519 over ton.blockId,
                        require signed_weight*3 >= total_weight*2
                      -> `to` becomes trusted
    blockLinkBack:    verify via header + state proofs into already-trusted state
  -> current MC block hash trusted, anchored to the pinned init key-block
```

Transport selection is orthogonal. On native the datagram path (UDP/DHT) and the
stream path (TCP/liteserver) both run. In the browser only the stream path runs,
over a WebSocket-to-liteserver proxy; DHT and UDP are unavailable there.

## State and storage

Almost none; the library is a client, not a node.

- **Ephemeral, in-memory:** ADNL session and channel keys, sequence counters, the
  in-flight query window, a short-lived Kademlia routing view per lookup, and the
  synced trusted-block state. Discarded when the client closes. Storage class:
  ephemeral (constitution §7); never persisted.
- **Caller-provided, read-only:** the global config and the pinned init key-block.
  Public data, no secret.
- **Never stored:** any user key, any wallet material, any query history. A
  consumer that caches (resolved addresses, synced blocks, TVM results) does so
  above the boundary and owns that decision.

## Failure and security

Failure paths:

- **Unreachable or silent peer** -> bounded per-query timeout; DHT moves to the
  next candidate; liteserver reconnects or fails with a clear cause. No hang.
- **Malformed packet** -> TL decode returns `ParseError`, the packet is dropped, a
  fuzz target guards this in CI. One dropped datagram, not a crash.
- **Forged DHT record** -> signature check fails, `BadSignature`.
- **Invalid or tampered proof** -> `BadProof`; the read fails rather than returning
  unverified data.
- **Amplification and flooding** -> bounded response buffers, a capped in-flight
  window, unsolicited datagrams dropped.

Custody and security:

- **Structurally, no user key can live here** (NET-ADR-001). Only ephemeral
  network keys; no user key anywhere; the type surface gives one no home.
  `sendMessage` broadcasts already-signed bytes.
- **Primary hardening targets:** the TL deserializer (total, bounded, fuzzed), the
  cell-hash and Merkle-proof verification (a wrong level mask or a skipped check
  silently breaks the trust guarantee), the block-sync signature check, and the
  TVM's resource bounds.
- **The one trust assumption is explicit:** the pinned init key-block, surfaced
  through `Sync.anchor`, not hidden. Everything after it is cryptographic.
- **Not provided:** node-level guarantees. This is a client; it consumes the
  two-thirds validator signatures, it does not participate in consensus.
