# TON wire-format map

The implementation-grade protocol reference for ton-net. Every fact here is drawn
from primary sources: the `ton_api.tl` and `lite_api.tl` schemas, the C++
reference in `ton-blockchain/ton`, and cross-checked against the pytoniq light
client. Constructor tags marked "verified" were reproduced empirically; the rest
are derivable by the CRC32 rule below.

This document exists because TON's own low-level documentation is scattered,
partly moved to `old-docs.ton.org`, and in places wrong (flagged inline). For a
community client library, a correct wire map is itself a contribution.

Canonical schema files (the pinned inputs):
- `tl/generate/scheme/ton_api.tl` (ADNL, DHT, RLDP, overlay, keys)
- `tl/generate/scheme/lite_api.tl` (the liteserver protocol)
- `crypto/block/block.tlb` (TL-B for Block, ShardState, Account, ...)

---

## TL serialization

- 32-bit word aligned, little-endian numbers, every object zero-padded to a
  4-byte boundary.
- `int` = 4 bytes, `long` = 8, `int256` = 32, `#` = uint32 flags word,
  `vector T` = int count then elements.
- `bytes` / string: length < 254 -> 1 length byte + data; length >= 254 -> `0xFE`
  + 3-byte LE length + data; then zero-pad to 4 bytes.
- **Boxed vs bare:** boxed prefixes the 4-byte constructor tag (used when the field
  type is abstract, so the parser can discriminate); bare has no prefix (used when
  the concrete constructor is named in the field type). `id:PublicKey` is boxed;
  `id:pub.ed25519` is bare.

### Constructor tags: CRC32-IEEE

The tag is **CRC-32/IEEE** (polynomial `0xEDB88320` reflected, init `0xFFFFFFFF`,
final XOR `0xFFFFFFFF`) over the normalized definition string, stored little-endian
as the first 4 bytes of a boxed object. **Not** CRC32-C / Castagnoli.

The hashed string is `"<id> <field>:<type> <field>:<type> ... = <ResultType>"`:
the constructor id with no leading space, each token separated by a single ASCII
space, field types written literally (`int256`, `long`, `bytes`), conditional
fields as `flags.N?type`, then ` = ` and the boxed result-type name. An explicit
`#<hex>` in the schema overrides the CRC.

Verified (via `zlib.crc32`, which is exactly this variant):

| normalized string | tag |
|---|---|
| `pub.ed25519 key:int256 = PublicKey` | `0x4813b4c6` |
| `pub.aes key:int256 = PublicKey` | `0x2dbcadd4` |
| `pub.overlay name:bytes = PublicKey` | `0x34ba45cb` |
| `pub.unenc data:bytes = PublicKey` | `0xb61f450a` |
| `adnl.message.query` | `0xb48bf97a` |
| `dht.findNode` | `0x6ce2ce6b` |
| `dht.ping` | `0xcbeb3f18` |

Regenerate the full set from the schema text; do not hand-copy.

---

## ADNL

### Identity and address

A peer identity is an Ed25519 keypair. The 256-bit ADNL address is the **boxed**
SHA256 of the public key: `SHA256(tag(pub.ed25519)_LE ‖ pubkey)` =
`SHA256(0xc6b41348_bytes ‖ 32-byte-pubkey)`. The same boxed-SHA256 helper backs
DHT key-ids. ECDH is X25519; Ed25519 keys are converted to Curve25519. The cipher
is AES-256-CTR with a 128-bit big-endian counter.

### ADNL over TCP (liteserver transport)

**256-byte handshake, client to server:**
```
[32] server ADNL short-id
[32] client ephemeral X25519 pubkey
[32] SHA256(nonce)
[160] AES-CTR(nonce)          // encrypted with a key derived from the ECDH shared secret
```
The `nonce` is 160 random bytes. **Correction to the old docs:** the temporary
AES key is derived from the **X25519 ECDH shared secret**, not the raw server
public key (the old-docs TCP page is wrong; the C++ and pytoniq are authoritative).

**Session keys** come from the first 96 bytes of the nonce:
```
s1 = nonce[0:32]   s2 = nonce[32:64]   v1 = nonce[64:80]   v2 = nonce[80:96]
client: rx = AES-CTR(s1, v1),  tx = AES-CTR(s2, v2)     // server mirrors
```

**Stream frame** (every packet, whole frame AES-CTR encrypted):
```
[4]  length (LE, = 32 + payload_len + 32, excludes itself)
[32] random nonce
[..] payload
[32] SHA256(nonce ‖ payload)
```
Minimum body 64 bytes; maximum `1 << 24`. The length is decrypted first, then the
body; the receiver verifies the trailing SHA256.

**Query nesting** over the stream:
```
adnl.message.query{ query_id, query = liteServer.query{ data = <liteServer.getXxx...> } }
```

### ADNL over UDP (peer-to-peer, DHT)

Packet to a peer = `[32] destination short-id ‖ EncryptorEd25519(serialized adnl.packetContents)`,
where the encryptor produces `[32] ephemeral pubkey ‖ [32] SHA256(plaintext) ‖ AES-CTR(plaintext)`
with `key = shared[0:16] ‖ sha256[16:32]`, `iv = sha256[0:4] ‖ shared[20:32]`.

`adnl.packetContents` (verbatim, `ton_api.tl`): `rand1:bytes, flags:#,
from:flags.0?PublicKey, from_short:flags.1?adnl.id.short, message:flags.2?adnl.Message,
messages:flags.3?(vector adnl.Message), address:flags.4?adnl.addressList,
priority_address:flags.5?adnl.addressList, seqno:flags.6?long,
confirm_seqno:flags.7?long, recv_addr_list_version:flags.8?int,
recv_priority_addr_list_version:flags.9?int, reinit_date:flags.10?int,
dst_reinit_date:flags.10?int, signature:flags.11?bytes, rand2:bytes`.

Flag bits (authoritative, from `adnl-packet.h`): from=0x1, from_short=0x2,
one_message=0x4, mult_messages=0x8, address=0x10, priority_address=0x20,
seqno=0x40, confirm_seqno=0x80, recv_addr_version=0x100,
recv_priority_addr_version=0x200, reinit_date=0x400, signature=0x800.
`rand1`/`rand2` are 7 or 15 random bytes. `seqno` is a per-peer-pair counter;
`confirm_seqno` acks the highest seqno received. Sign by serializing with the
signature field off, Ed25519-signing, then re-serializing with it set. **The stale
flag comment in `adnl-packet.cpp` is wrong; the `.h` enum and `.tl` are correct.**

**Channels:** `adnl.message.createChannel key:int256 date:int` /
`adnl.message.confirmChannel key:int256 peer_key:int256 date:int` exchange
ephemeral Ed25519 channel keys; the X25519 shared secret and its byte-reverse give
two AES keys, assigned by comparing the two channel short-ids as uint256.

---

## DHT (Kademlia)

Parameters (from `dht.hpp`): **k = 10** (bucket width, `findNode` count),
**a = 3** (query parallelism), both config-driven via `dht.config.global ... k:int
a:int`, clamped to maxima 10. Distance is XOR of key-ids.

**Key-id:** `SHA256(boxed dht.key{id:int256, name:bytes, idx:int})`. `name` is
`"address"` for ADNL address records, `"nodes"` for shard-overlay records.

Read: `dht.findValue key:int256 k:int` returns `dht.valueFound value:dht.Value`
or `dht.valueNotFound nodes:dht.nodes` (iterate toward closer nodes).
`dht.findNode key:int256 k:int`, `dht.getSignedAddressList`.

Write: `dht.store value:dht.value`. To publish an address, build
`dht.value{ key:dht.keyDescription{ key:dht.key{id, name:"address", idx:0}, id:<PublicKey>,
update_rule:dht.updateRule.signature, signature }, value:<serialized adnl.addressList>,
ttl, signature }`, signing both the key description and the value, then store to the
k closest nodes found via `findNode`.

Every DHT request is prefixed by a serialized `dht.query{node}` carrying the
sender's own `dht.node`. Signature check everywhere: zero the signature field,
re-serialize, Ed25519-verify against the record's `id`.

---

## Liteserver methods

Wrapped as `adnl.message.query` over `liteServer.query`. The client method set
(`lite_api.tl`), with which responses carry Merkle proofs:

| Method | Proof in response |
|---|---|
| `getMasterchainInfo` / `getMasterchainInfoExt` | state_root_hash only |
| `getTime` / `getVersion` | none |
| `getBlock` / `getState` | block/state BoC |
| `getBlockHeader` | header_proof |
| `sendMessage` | none (status int, unprovable) |
| `getAccountState` / `getAccountStatePrunned` | shard_proof + proof |
| `runSmcMethod` | shard_proof + proof + state_proof (result NOT proven) |
| `getShardInfo` / `getAllShardsInfo` | shard_proof / proof |
| `getOneTransaction` / `getTransactions` | proof / tx-chain BoC |
| `listBlockTransactions(Ext)` | proof (optional) |
| `getBlockProof` | the proof chain (block links) |
| `getConfigAll` / `getConfigParams` | state_proof + config_proof |
| `lookupBlock` / `lookupBlockWithProof` | header_proof / mc-state + block proofs |
| `getShardBlockProof` | shardBlockLink.proof |
| `getLibrariesWithProof` | state_proof + data_proof |

Explicit-magic constructors (hardcoded, not CRC-derived): `liteServer.transactionId#b12f65af`,
`liteServer.signatureSet.ordinary#f644a6e6`, `liteServer.getValidatorStats#091a58bc`.

Key response types (verbatim):
```
liteServer.accountState id shardblk shard_proof:bytes proof:bytes state:bytes
liteServer.runMethodResult mode:# id shardblk shard_proof:mode.0?bytes proof:mode.0?bytes
    state_proof:mode.1?bytes init_c7:mode.3?bytes lib_extras:mode.4?bytes
    exit_code:int result:mode.2?bytes
liteServer.blockLinkForward to_key_block:Bool from to dest_proof:bytes
    config_proof:bytes signatures:liteServer.SignatureSet
liteServer.blockLinkBack to_key_block:Bool from to dest_proof:bytes proof:bytes state_proof:bytes
liteServer.partialBlockProof complete:Bool from to steps:(vector liteServer.BlockLink)
liteServer.signature node_id_short:int256 signature:bytes
```

---

## Proof verification

Proofs are exotic cells: `pruned_branch` (type 1), `merkle_proof` (3),
`merkle_update` (4). Verify pattern: a `merkle_proof`'s virtual-root hash
(`refs[0].get_hash(0)`) must equal a trusted hash; then every un-pruned cell in it
is trusted. Cell hashing must handle **level masks** (a pruned cell carries higher-
level hashes; using level-0 hashes only, as pytoniq's incomplete code does, is a
bug on the trust path).

The five routines (matching C++ `check-proof.h`): `check_block_header_proof`,
`check_shard_proof`, `check_account_proof`, `check_state_proof`,
`check_extract_state_proof`.

The canonical account read chains them: shard proof (MC block -> trusted shard
block) then account proof (shard block -> trusted account hash), then assert the
returned state's representation hash equals that trusted hash.

---

## Block sync (the trust anchor)

Layer-1, which the TON docs describe and then explicitly defer to a nonexistent
"future article"; the authority is `lite_api.tl` block-links plus C++
`check-proof.cpp` plus pytoniq `sync.py`.

- Anchor: a pinned masterchain **key-block** `BlockIdExt` (root_hash + file_hash +
  seqno), obtained out-of-band. `config.validator.init_block` carries it.
- `getMasterchainInfo` gives an untrusted head. `getBlockProof(known, target)`
  returns `partialBlockProof` steps.
- **blockLinkForward:** verify `check_block_header_proof(dest_proof, to.hash)`;
  derive the validator set from the `from` key-block (config param 34
  cur_validators, param 28 for selection); check signatures: each
  `liteServer.signature` is Ed25519 over `TL(ton.blockId root_cell_hash file_hash)`;
  require `signed_weight*3 >= total_weight*2`. `from` trusted and 2/3-signing `to`
  makes `to` trusted.
- **blockLinkBack:** step to an older block referenced in an already-trusted
  state, verified by header and state proofs.
- Key blocks form the backbone: each key block's config names the next validator
  set, so forward links carry trust across validator rotations.

**Known reference gaps to implement correctly (not copy):** pytoniq's
`compute_validator_set` stubs the MC shuffle and shard-validator selection, and its
proof code has a level-mask TODO. A correct ton-net implements the real
`ShardStateUnsplit` / config-28/34 selection and full level-mask hashing.

---

## Not provable, by construction

- **`runSmcMethod` result:** proofs cover the account code, data, and c7, not the
  computation. Trustless get-methods require the local TVM (NET-ADR-005).
- **`sendMessage`:** broadcast into the mempool, returns only a status int.
  Trust-minimization means verifying the *effect* afterward (prove the resulting
  account state or transaction), not the send.
