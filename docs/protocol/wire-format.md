<!--
SPDX-License-Identifier: Apache-2.0
SPDX-FileCopyrightText: 2026 Nirapod Labs
-->

# ton-net wire format

This is the reference for the bytes ton-net puts on the wire and reads back from a TON
liteserver. Three protocols stack to make one query travel:

- **The TL codec**, TON's Type Language: a constructor-tagged binary encoding. Every
  message below is a TL type. Defined in `ton-net-tl`.
- **ADNL**, the encrypted transport TON nodes speak: a fixed handshake packet, then a
  stream of framed messages under two AES-256-CTR keystreams. Defined in `ton-net-adnl`.
- **The liteserver query layer**, the `liteServer.*` request and response set a read
  client speaks over ADNL. Query construction and answer decoding are in `ton-net-lite`;
  the message types are in `ton-net-tl`.

The split between the pure protocol core and the I/O that carries it follows NET-ADR-002:
the handshake and the framing are synchronous functions over bytes, tested against fixed
vectors, and the one socket sits behind a two-method transport seam. This document
describes the bytes, not the socket.

One property holds throughout the codec and the transport: nothing here checks a proof or
a signature. A decoded response is the server's word. Verification of Merkle proofs and
validator signatures belongs to layers above the ones this document covers. Every claim
below is grounded in the crate source and its tests; the source file is named at each
point, and the constructor-id and constant tables at the end list every value with its
origin.

Numbers are written in hexadecimal with a `0x` prefix for constructor ids and byte
values, and in decimal for sizes and counts. A byte sequence written `2e e6 b5 89` is in
wire order, low byte first.

## 1. The TL codec

TON's Type Language describes each message as a typed record. `ton-net-tl` defines the
records the client needs as Rust types and derives their encoders and decoders over the
`tl-proto` crate, so a caller serializes and deserializes typed values and never handles
the tags by hand (`crates/ton-net-tl/src/lib.rs`).

### 1.1 Boxed and bare types

A TL type is either boxed or bare.

- A **boxed** type carries a four-byte **constructor id** as its first bytes. The id is
  the IEEE CRC-32 of the type's TL scheme line, written little-endian on the wire. It
  names which constructor produced the bytes, so a decoder reading a union knows which
  arm it holds.
- A **bare** type carries no id. It appears only as a field of another type, where the
  outer type's definition already fixes what it is.

The constructor id is computed by the standard CRC-32 with the reflected polynomial
`0xEDB88320`, initial value `0xFFFFFFFF`, and a final complement. The scheme line hashed
is the full TL definition: the constructor name, each field as `name:type`, and the
`= ResultType` tail. The wire-format test reproduces that CRC and checks every boxed
type's declared id against the CRC of its scheme line
(`crates/ton-net-tl/tests/wire.rs`, `constructor_ids_match_scheme`).

Worked example. The scheme line

```text
liteServer.getMasterchainInfo = liteServer.MasterchainInfo
```

hashes to `0x89b5e62e`, which written little-endian is `2e e6 b5 89`. A nullary boxed
request serializes to exactly its constructor id, so this request is those four bytes and
nothing more. The crate's own doctest asserts it (`crates/ton-net-tl/src/lib.rs`):

```rust
assert_eq!(ton_net_tl::serialize(GetMasterchainInfo), [0x2e, 0xe6, 0xb5, 0x89]);
```

### 1.2 Primitive field encodings

The primitives below are what the TL scheme names, encoded as `tl-proto` writes them. Each
width is fixed by a layout the tests pin; the relevant test is named where it settles a
size.

| TL type | Encoding | Width |
|---|---|---|
| `int` | little-endian signed integer | 4 bytes |
| `long` | little-endian integer | 8 bytes |
| `int256` | 32 raw bytes, copied verbatim (a hash or a key) | 32 bytes |
| `#` (nat) | little-endian unsigned integer, used for flag words | 4 bytes |
| `Bool` | boxed: a constructor id, `boolTrue` is `0x997275b5` | 4 bytes |
| `bytes`, `string` | length-prefixed, then padded to a four-byte boundary | variable |
| `vector t` | a 4-byte little-endian count, then that many elements | variable |

`bytes` and `string` share one length-prefixed form. A short value is written as a single
length byte, then the data, then zero padding up to the next four-byte boundary. A long
value is written as the marker byte `0xfe`, then a three-byte little-endian length, then
the data, then padding. The single-byte case is visible in the query wrapping of section
6.1 (the `0x04` and `0x0c` prefixes); the `0xfe` marker is exercised by a hostile-length
test that rejects a prefix claiming roughly 16 MB with no data behind it
(`crates/ton-net-tl/tests/wire.rs`, `hostile_length_prefix_is_rejected`).

The `int256`, `int`, and `long` widths together fix the size of a `tonNode.blockIdExt` at
80 bytes (a 4-byte workchain, an 8-byte shard, a 4-byte seqno, and two 32-byte hashes),
which the block-proof request layout depends on (section 6.2) and a test asserts
(`crates/ton-net-tl/tests/wire.rs`, `the_mode_word_follows_the_target_block`). The `#`
width is fixed at 4 bytes by that same test's mode word. The `boolTrue` id and the
4-byte vector count are both fixed by a test that builds a `liteServer.partialBlockProof`
header by hand (`crates/ton-net-tl/tests/wire.rs`, `a_hostile_vector_length_does_not_allocate`).

A boxed field that is optional, written `mode.0?type` in a scheme, is present in the bytes
only when the flag bit it names is set in the preceding `#` word. Section 6.2 covers the
one request that uses this.

### 1.3 The decoder's posture

The codec reads bytes from a server the client does not trust, so its failure mode is
fixed by lints: `ton-net-tl` denies panicking, indexing, and unwrapping in library code,
so a decoder returns an error rather than unwinding (`crates/ton-net-tl/src/lib.rs`). A
panic in a decoder would be a denial of service in whatever process embedded the client.

Three behaviors follow, each pinned by a test in `crates/ton-net-tl/tests/wire.rs`:

- **No input panics.** A fixed-seed generator feeds 50,000 pseudo-random byte strings to
  every deserializer; each must resolve to `Ok` or `Err`, never a panic
  (`decode_never_panics_on_arbitrary_bytes`).
- **A declared count is bounded by what remains.** A vector claiming four billion
  elements with none present is refused before any allocation follows the count
  (`a_hostile_vector_length_does_not_allocate`). The decoder bounds the count by the bytes
  left in the buffer rather than reserving for the claim.
- **An unknown constructor is refused, not guessed.** A union arm whose id no version of
  the client knows returns `TlError::UnknownConstructor` rather than being read as some
  other arm (`an_unknown_signature_set_is_refused_rather_than_read`,
  `an_unknown_block_link_is_refused_rather_than_read`). This matters most where two arms
  share a field layout; section 7.2 covers the case.

## 2. The ADNL handshake

A session with a liteserver opens with one packet from the client. From the moment it is
sent, both sides share the two stream ciphers that frame everything after. The handshake
is a pure function of a server key and fresh randomness; the code that builds it touches
no socket, no clock, and no randomness source of its own
(`crates/ton-net-adnl/src/handshake.rs`, and NET-ADR-002 for the sans-I/O seam).

### 2.1 The packet

The packet is exactly 256 bytes, laid out as four fields:

```text
server_key_id (32) ++ client_pub (32) ++ checksum (32) ++ encrypted_params (160)
```

- **`server_key_id`** names which server key the client used, so a server holding several
  keys can pick the matching private one. It is the SHA-256 of the server's public key in
  its TL `pub.ed25519` form, which is the constructor id `0x4813b4c6` written
  little-endian followed by the 32 key bytes. The same computation names a validator by
  its key elsewhere (section 7.3).
- **`client_pub`** is an ephemeral public key, the compressed Edwards form of the key
  derived from the handshake seed.
- **`checksum`** is the SHA-256 of the 160 session parameters, carried in the clear.
- **`encrypted_params`** is those 160 parameters under a cipher keyed by the shared
  secret and the checksum, so only the holder of the matching server private key can
  recover them.

### 2.2 The key exchange

The ephemeral scalar is the first 32 bytes of `SHA-512(key_seed)`. The client public key
is `scalar` times the Edwards base point, compressed to 32 bytes. The shared secret is the
X25519 Diffie-Hellman of `scalar` with the server key converted to its Montgomery form.
Both the base-point multiply and the shared-secret multiply apply the RFC 7748 clamp, so
the key sent and the secret derived rest on one scalar
(`crates/ton-net-adnl/src/handshake.rs`).

Two server keys are refused:

- A key that does not decode to a valid Edwards point yields
  `HandshakeError::InvalidServerKey`. No shared secret can be derived from a non-point.
- A key of small order decodes as a point but multiplies to the all-zero secret, because
  the clamp forces the scalar to a multiple of the cofactor. The handshake aborts with
  `HandshakeError::DegenerateSharedSecret`, per RFC 7748 section 6.1. A zero secret would
  leave the handshake key as sixteen zero bytes followed by half of a checksum the packet
  carries in the clear, handing the session to anyone watching the packet
  (`crates/ton-net-adnl/src/handshake.rs`, tests `a_non_point_server_key_is_rejected` and
  `a_small_order_server_key_is_rejected`).

### 2.3 The handshake cipher over the parameters

The 160 parameters are wrapped with AES-256-CTR under a key and iv derived from the shared
secret and the checksum:

- key = `shared[..16] ++ checksum[16..]`
- iv = `checksum[..4] ++ shared[20..]`

The stream cipher is `Ctr128BE<Aes256>`, AES-256 in counter mode with a 128-bit
big-endian counter (`crates/ton-net-adnl/src/lib.rs`). A party holding the shared secret,
and only such a party, can recover the parameters and so the session ciphers. A unit test
reconstructs the key and iv from the shared secret and decrypts the packet tail back to
the original parameters (`crates/ton-net-adnl/src/handshake.rs`,
`encrypted_params_decrypt_back_to_params`).

### 2.4 The randomness a handshake consumes

One handshake needs 192 bytes of fresh randomness: a 32-byte seed for the ephemeral key
and the 160 session parameters. The building function takes this as an input value
(`HandshakeSecrets`) so it stays pure. The one draw from the operating system happens in
the async connection driver at the I/O edge, through `getrandom`
(`crates/ton-net-adnl/src/handshake.rs`, `crates/ton-net-adnl/src/connection.rs`). The
same 192 bytes must never be reused across two handshakes.

## 3. Session framing

Once the handshake is sent, each direction of the session is an AES-256-CTR stream whose
keystream runs continuously across every frame (`crates/ton-net-adnl/src/frame.rs`).

### 3.1 The frame

One frame on the wire is:

```text
length (u32 LE) ++ nonce (32) ++ payload ++ checksum (32)
```

- **`length`** counts the bytes after it, so the frame body is `32 + payload + 32`.
- **`nonce`** is 32 fresh random bytes, making each frame's ciphertext unique even when
  the payload repeats.
- **`checksum`** is `SHA-256(nonce ++ payload)`, which lets the receiver reject a
  corrupted or desynchronized frame.

The whole frame, length prefix included, is encrypted under the sending direction's
keystream. A sealed frame with an empty payload is therefore `4 + 64` bytes; a sealed
frame with an 18-byte payload is `4 + 32 + 18 + 32 = 86` bytes
(`crates/ton-net-adnl/src/frame.rs`, tests `seals_and_opens_an_empty_payload` and the
pinned vector in `crates/ton-net-adnl/tests/vectors.rs`).

### 3.2 The two session ciphers

A session holds two ciphers. `rx` decrypts bytes from the server; `tx` encrypts bytes to
it. The client seeds them from the 160 session parameters:

- `rx` key = `params[0..32]`, `rx` iv = `params[64..80]`
- `tx` key = `params[32..64]`, `tx` iv = `params[80..96]`

The server derives the mirror image from the same parameters, so a frame the client seals
with `tx` opens on the server with its `rx` (`crates/ton-net-adnl/src/frame.rs`,
`from_params`; the test `peer` helper builds the mirror). Parameter bytes `96..160` are
carried in the handshake but are not consumed by this seeding.

Because a counter-mode keystream advances with every byte it processes, the two ends count
in step. A frame must be opened in the same order it was sealed. Opening out of order
desynchronizes the stream, and every later frame fails to open
(`opening_out_of_order_desyncs`). A frame sealed under one session's parameters does not
open under another's (`a_different_session_cannot_open_a_frame`).

### 3.3 Frame bounds

The frame body is accepted only in the range `64 ..= 16777216` bytes (`MIN_FRAME` to
`MAX_FRAME`, which is `1 << 24`). Both ends are load-bearing:

- A body shorter than 64 cannot hold a nonce and a checksum, so it means the stream is
  desynchronized (`FrameError::BodyTooShort`).
- A decrypted length prefix outside the range is what a wrong handshake looks like on the
  first frame: a mismatched session decrypts the length to garbage. It is refused as
  `FrameError::ImplausibleLength` before any allocation follows it.

`MAX_FRAME` is the protocol's own ceiling, not a guess at how large an honest reply is. A
measured mainnet block-proof reply is already 713 kB, so a tighter bound would refuse
honest traffic the day a server sends a few more links. The bounds that limit real work,
the link count, the proof sizes, and the signature counts a client will check, live in the
`ton-net` facade, all well under this ceiling
(`crates/ton-net-adnl/src/frame.rs`).

Sealing a payload that would exceed the ceiling returns `FrameError::PayloadTooLarge`
before anything is sealed, so the send keystream does not move. Refusing after sealing
would desynchronize the stream instead (`seal`, and
`a_payload_past_the_ceiling_is_refused_without_moving_the_keystream`).

### 3.4 Opening a frame

Opening is two steps against the shared keystream position. `open_len` decrypts the
four-byte length prefix, advancing the `rx` keystream by four bytes, and returns the body
length to read. `open_body` then decrypts exactly that many bytes, splits off the nonce
and checksum, and rejects the frame with `FrameError::Checksum` if
`SHA-256(nonce ++ payload)` does not match the stored checksum
(`crates/ton-net-adnl/src/frame.rs`). A single flipped byte inside the body fails this
check (`a_tampered_payload_is_rejected`).

Because both steps move the keystream, they must run in order and to completion. The
connection driver guards this with an `intact` flag, lowered before a frame starts moving
and raised only once it has finished; an interruption in between leaves it lowered, and
the session is reported as `Desynchronized` on the next use rather than silently reading
from the wrong keystream position (`crates/ton-net-adnl/src/connection.rs`).

## 4. The ADNL message envelope

Inside a frame's payload rides an `adnl.Message`. The client sends a query and the server
replies with an answer echoing the same id (`crates/ton-net-tl/src/adnl.rs`).

| Scheme line | Constructor id | Role |
|---|---|---|
| `pub.ed25519 key:int256 = PublicKey` | `0x4813b4c6` | the key form hashed into a `server_key_id` |
| `adnl.message.query query_id:int256 query:bytes = adnl.Message` | `0xb48bf97a` | a query and its opaque payload |
| `adnl.message.answer query_id:int256 answer:bytes = adnl.Message` | `0x0fac8416` | the answer echoing `query_id` |

A query pairs a caller-chosen 32-byte `query_id` with a serialized request payload. The
answer returns the same `query_id` with the response payload, so a caller matches a reply
to its request. For the liteserver path the query payload is a serialized
`liteServer.query` (section 6.1).

The connection driver wraps each outgoing request in an `adnl.message.query` with a fresh
random `query_id`, seals it into a frame, and reads frames until an `adnl.message.answer`
echoes that id (`crates/ton-net-adnl/src/connection.rs`, `query`). Two rules shape the read
loop:

- A frame whose decrypted payload is empty is an ADNL confirmation frame and carries no
  message; it is skipped.
- At most 8 frames are read per query (`MAX_FRAMES_PER_QUERY`). If no matching answer
  arrives within that budget, the driver returns `NoAnswer`; if every frame in the budget
  decrypted and passed its checksum but decoded to no known ADNL message, it returns
  `Malformed`.

ADNL defines more message kinds than the two modeled here. A frame that decrypts and
checks out but names an unmodeled message is treated as a gap in what is decoded, not a
broken stream: it is skipped like any other non-answer, and the stream position stays
known because the frame was read whole (`crates/ton-net-adnl/src/connection.rs`).

## 5. The liteserver query layer

The liteserver read protocol is a set of `liteServer.*` request and response types
(`crates/ton-net-tl/src/lite.rs`), driven by `ton-net-lite`
(`crates/ton-net-lite/src/client.rs`). Every response is the server's word; this layer
decodes it and checks neither the Merkle proofs nor the validator signatures a liteserver
returns.

### 5.1 The three-layer wrapping

A liteserver method travels inside two envelopes:

1. The method (for example `liteServer.getMasterchainInfo`) is serialized on its own.
2. Those bytes become the `data` field of a `liteServer.query`
   (`liteServer.query data:bytes = Object`, id `0x798c06df`), which is serialized again.
3. The `liteServer.query` bytes become the `query` field of an `adnl.message.query`
   (section 4), sealed into a frame and sent.

The wrapping is worked out byte for byte in a test that reproduces the exact query a
mainnet liteserver accepted in the feasibility spike
(`crates/ton-net-tl/tests/wire.rs`, `query_wire_layout_matches_mainnet_spike`;
`crates/ton-net-lite/src/client.rs`, `build_query_wraps_the_request_as_a_liteserver_query`).
For `getMasterchainInfo`:

```text
liteServer.query wrapping (12 bytes):
  df 06 8c 79            liteServer.query id (0x798c06df, little-endian)
  04                     bytes length of the inner method (4)
  2e e6 b5 89            liteServer.getMasterchainInfo id
  00 00 00               padding to a 4-byte boundary

full adnl.message.query (52 bytes):
  7a f9 8b b4            adnl.message.query id (0xb48bf97a, little-endian)
  AA * 32                the caller-chosen query_id
  0c                     bytes length of the query payload (12)
  df 06 8c 79 04 2e e6 b5 89 00 00 00   the 12-byte liteServer.query above
  00 00 00               padding to a 4-byte boundary
```

The inner method sits behind two `bytes` length prefixes, each padded to a four-byte
boundary. That double wrapping is why a 4-byte request travels as a 52-byte ADNL message.

### 5.2 Requests

| Scheme line | Constructor id | Answers with |
|---|---|---|
| `liteServer.getMasterchainInfo = liteServer.MasterchainInfo` | `0x89b5e62e` | `liteServer.masterchainInfo` |
| `liteServer.getTime = liteServer.CurrentTime` | `0x16ad5a34` | `liteServer.currentTime` |
| `liteServer.getVersion = liteServer.Version` | `0x232b940b` | `liteServer.version` |
| `liteServer.getAccountState id:tonNode.blockIdExt account:liteServer.accountId = liteServer.AccountState` | `0x6b890e25` | `liteServer.accountState` |
| `liteServer.getBlockProof mode:# known_block:tonNode.blockIdExt target_block:mode.0?tonNode.blockIdExt = liteServer.PartialBlockProof` | `0x8aea9c44` | `liteServer.partialBlockProof` |

`getAccountState` names a masterchain block and an account. `getBlockProof` asks the
server to connect a block the client already trusts to a later one.

The `mode` word of `getBlockProof` is a flag set whose only flag, bit 0, says whether a
target block follows. In this client the field is derived from the target rather than
carried, so the flag word and the field cannot disagree. With the target present, the
request is `4 + 4 + 80 + 80 = 168` bytes and the mode word is `01 00 00 00`; with the
target absent, the request is `4 + 4 + 80 = 88` bytes and the mode word is `00 00 00 00`
(`crates/ton-net-tl/tests/wire.rs`, `the_mode_word_follows_the_target_block`). The read
client always supplies a target: a client walking toward a head it has already chosen
gains nothing from letting the server pick the destination
(`crates/ton-net-lite/src/client.rs`, `block_proof`).

### 5.3 Responses

| Scheme line | Constructor id |
|---|---|
| `liteServer.masterchainInfo last:tonNode.blockIdExt state_root_hash:int256 init:tonNode.zeroStateIdExt = liteServer.MasterchainInfo` | `0x85832881` |
| `liteServer.currentTime now:int = liteServer.CurrentTime` | `0xe953000d` |
| `liteServer.version mode:# version:int capabilities:long now:int = liteServer.Version` | `0x5a0491e5` |
| `liteServer.accountState id:tonNode.blockIdExt shardblk:tonNode.blockIdExt shard_proof:bytes proof:bytes state:bytes = liteServer.AccountState` | `0x7079c751` |
| `liteServer.error code:int message:string = liteServer.Error` | `0xbba9e148` |

`masterchainInfo` carries the server's current masterchain head, the masterchain state
root hash, and the zero state. `version` carries a reserved mode word, the liteserver
version, a capability bitmask, and the server's current time. `accountState` carries the
masterchain block the state was read at, the shard block that holds the account, and three
raw bag-of-cells fields: the shard proof linking the masterchain block to the shard block,
the proof of the account state within the shard block, and the account state itself. This
layer parses none of those cell trees.

A real `liteServer.masterchainInfo` captured from a mainnet liteserver decodes and
re-encodes to the exact captured bytes, which anchors the response layout to TON rather
than to this crate's encoder (`crates/ton-net-tl/tests/wire.rs`,
`decodes_a_real_mainnet_masterchain_info`; the capture is at masterchain seqno 80945431).

### 5.4 Shared identifiers

Three bare types recur as fields (`crates/ton-net-tl/src/lite.rs`):

- `tonNode.blockIdExt` is a full block identifier: workchain (`int`), shard (`long`),
  seqno (`int`), root hash (`int256`), and file hash (`int256`), 80 bytes in all. The
  masterchain workchain is `-1` and its shard is `0x8000000000000000`.
- `tonNode.zeroStateIdExt` is a workchain's genesis identity: workchain, root hash, file
  hash.
- `liteServer.accountId` is a workchain and a 256-bit account id.

Being bare, they carry no constructor id and are read positionally as fields of the boxed
types that hold them.

### 5.5 The error path

A liteserver answers a query with either the expected response or a `liteServer.error`.
The two carry distinct constructor ids, so the read client first tries to decode the
answer as `liteServer.error`; a success there surfaces as a `LiteError::LiteServer` with
the server's code and message, and anything else is decoded as the expected response type
(`crates/ton-net-lite/src/client.rs`, `decode_answer`). Bytes that are neither the error
nor the expected response are a decode failure.

## 6. Block proofs and the signed forms

A block proof is what turns a block the client already trusts into a later one it can also
trust. The server picks the route and the client validates every step, believing nothing
about the route itself, including whether it runs forward
(`crates/ton-net-tl/src/lite.rs`).

### 6.1 The proof chain

| Scheme line | Constructor id |
|---|---|
| `liteServer.partialBlockProof complete:Bool from:tonNode.blockIdExt to:tonNode.blockIdExt steps:vector liteServer.BlockLink = liteServer.PartialBlockProof` | `0x8ed0d2c1` |
| `liteServer.blockLinkForward to_key_block:Bool from:tonNode.blockIdExt to:tonNode.blockIdExt dest_proof:bytes config_proof:bytes signatures:liteServer.SignatureSet = liteServer.BlockLink` | `0x520fce1c` |
| `liteServer.blockLinkBack to_key_block:Bool from:tonNode.blockIdExt to:tonNode.blockIdExt dest_proof:bytes proof:bytes state_proof:bytes = liteServer.BlockLink` | `0xef7e1bef` |

A `partialBlockProof` is as much of a chain as the server chose to send at once: a
`complete` flag, the blocks it runs `from` and `to`, and a vector of steps. When `complete`
is false the chain stops short of the requested target and the caller asks again from
where the answer ended.

A step is a `liteServer.BlockLink` in one of two directions:

- A **forward** link goes from a key block to a later block and is carried by the
  signatures of the validator set that key block named. It holds a proof of the
  destination header, a proof of the source key block's configuration (which is where the
  signing validator set comes from), and the signature set over the destination. All proof
  fields are raw bag-of-cells bytes.
- A **backward** link goes the other way and cannot use signatures, because a block is not
  signed by validators who came later. It shows instead that the destination is recorded in
  the source block's state, carrying a proof of the destination header, a proof of the
  source block, and a proof of the source block's state.

Two whole answers captured from a mainnet liteserver, one per signed form, decode and
re-encode byte for byte, which pins the layout to TON
(`crates/ton-net-tl/tests/wire.rs`, `a_captured_block_proof_round_trips_byte_for_byte`).
The captures are one forward link each: masterchain 46894135 to 46897112 in the ordinary
form, and 59238081 to 59379986 in the simplex form
(`crates/ton-net-tl/tests/fixtures/`).

The block-proof types cross the read client as their wire form rather than a cleaned-up
twin, because their reader is a verifier and every field is evidence
(`crates/ton-net-lite/src/lib.rs`, `crates/ton-net-lite/src/client.rs`).

### 6.2 The signature set and its two forms

A forward link's signatures come as a `liteServer.SignatureSet`, which has taken two forms
on mainnet. Each signature inside is a `liteServer.signature`, a bare type holding the
signer's short id (`node_id_short`, the SHA-256 of the signer's key in `pub.ed25519` form)
and the 64-byte ed25519 signature.

| Scheme line | Constructor id |
|---|---|
| `liteServer.signatureSet validator_set_hash:int catchain_seqno:int signatures:vector liteServer.signature = liteServer.SignatureSet` | `0xf644a6e6` |
| `liteServer.signatureSet.simplex cc_seqno:int validator_set_hash:int signatures:vector liteServer.signature session_id:int256 slot:int candidate:bytes = liteServer.SignatureSet` | `0xac249800` |

The **ordinary** form signs a block identity directly. The **simplex** form comes from
TON's Simplex consensus and signs a vote naming a candidate, so the block is reached
through the candidate rather than signed outright. Mainnet changed form at masterchain
block 59379986, and a chain spanning that point carries both
(`crates/ton-net-tl/src/lite.rs`).

The two forms are a genuine hazard, which is why the constructor id is load-bearing here.
Their first two integer fields are in opposite order: the ordinary form is
`validator_set_hash` then `catchain_seqno`, the simplex form is `cc_seqno` then
`validator_set_hash`. A set relabelled as the other form decodes cleanly with its fields
silently swapped, and nothing later in the bytes catches it. The constructor id is the
only thing keeping the two apart, so a third form no version of the client knows is refused
by name rather than read as a best guess
(`crates/ton-net-tl/tests/wire.rs`,
`the_set_id_is_the_only_thing_keeping_the_two_forms_apart`,
`an_unknown_signature_set_is_refused_rather_than_read`).

### 6.3 The messages a signature covers

A signature in a set is 64 bytes and a signer id, and says nothing about what was signed.
A client that checks one rebuilds the exact bytes the validator's key went over. These are
the signed forms (`crates/ton-net-tl/src/signed.rs`). They are written and never read in
normal use: a client builds one to check a signature against it.

| Scheme line | Constructor id |
|---|---|
| `ton.blockId root_cell_hash:int256 file_hash:int256 = ton.BlockId` | `0xc50b6e70` |
| `ton.blockIdApprove root_cell_hash:int256 file_hash:int256 = ton.BlockId` | `0x2dd44a49` |
| `consensus.candidateId slot:int hash:int256 = consensus.CandidateId` | `0xb691cd3f` |
| `consensus.simplex.notarizeVote id:consensus.CandidateId = consensus.simplex.UnsignedVote` | `0xcdf605a8` |
| `consensus.simplex.finalizeVote id:consensus.CandidateId = consensus.simplex.UnsignedVote` | `0x40a7e105` |
| `consensus.dataToSign session_id:int256 data:bytes = consensus.DataToSign` | `0xa8e33df8` |
| `consensus.candidateHashDataOrdinary block:tonNode.blockIdExt ...` | `0xe8f9bcdc` |
| `consensus.candidateHashDataEmpty block:tonNode.blockIdExt ...` | `0x72b4d933` |

**The ordinary form.** `ton.blockId` is the whole of the older signed message, 68 bytes
with its constructor id: two 32-byte hashes behind the 4-byte id. The file hash is the
load-bearing field. It is the one part of a block identity no Merkle proof can establish,
being a hash of the serialized block file rather than of the cell tree, so a forward link's
destination is believed only after its signatures check, not after its header proof checks.

`ton.blockIdApprove` shares `ton.blockId`'s scheme result type and field layout and differs
only in its constructor id. It is not what a block proof's signatures cover; it is the
negative control that keeps that from being an assumption. A client checking a real set
against the wrong constructor finds every signature invalid, which looks exactly like a
forged set (`crates/ton-net-tl/src/signed.rs`, and
`crates/ton-net-tl/tests/wire.rs` for the id checks).

**The simplex form.** A Simplex signature covers a `consensus.dataToSign`, assembled as:

```text
DataToSign { session_id, data = Vote::Finalize { id = CandidateId { slot, hash } } }
```

The vote travels inside `dataToSign` as a `bytes` field, so it carries a length and padding
rather than sitting flush against the session id. The session id is signed alongside the
vote, so a signature raised in one consensus session cannot be replayed into another. A
block proof rests on the `finalizeVote` arm, because finalization is what commits a block;
the `notarizeVote` arm is its near neighbour and serves as the negative control the way
`blockIdApprove` does for the ordinary form. Both vote unions have a third member this
client never builds. `CandidateId.hash` is the SHA-256 of the candidate bytes the signature
set carries; nothing in the signed module hashes, so that digest is computed by the caller
and the digest crates stay out of the codec (`crates/ton-net-tl/src/signed.rs`).

**Which block a candidate names.** A simplex signature covers a vote naming a candidate by
hash, which on its own says nothing about which block that candidate was. A set of real
signatures lifted from one block and attached to a link claiming another would verify. The
candidate bytes travel with the set precisely so a client can read the block out of them.
`consensus.candidateHashData` has two constructors, ordinary and empty, and both open with
a `tonNode.blockIdExt`. The reader for this type implements no writer and reads only that
opening block identity, tolerating trailing bytes; the bytes after the identity are covered
by the hash the vote already signs (`crates/ton-net-tl/src/signed.rs`, `CandidateBlock`,
`read_prefix`). The empty form names the block an empty slot extends rather than a
proposal, and because Simplex finalization is transitive, finalizing an empty slot
finalizes its nearest ordinary ancestor. The two constructors therefore say the same thing
about the block they name, so the reader unions them.

## 7. Constructor id reference

Every boxed type the client encodes or decodes, with the constructor id declared in source
and checked against the CRC-32 of its scheme line
(`crates/ton-net-tl/tests/wire.rs`, `constructor_ids_match_scheme`). The id is the 32-bit
value; on the wire it is written little-endian. Bare types carry no id and are listed after.

### ADNL envelope (`crates/ton-net-tl/src/adnl.rs`)

| TL name | Constructor id | Rust type |
|---|---|---|
| `pub.ed25519` | `0x4813b4c6` | `adnl::PublicKey` |
| `adnl.message.query` | `0xb48bf97a` | `adnl::Message::Query` |
| `adnl.message.answer` | `0x0fac8416` | `adnl::Message::Answer` |

### Liteserver requests and responses (`crates/ton-net-tl/src/lite.rs`)

| TL name | Constructor id | Rust type |
|---|---|---|
| `liteServer.query` | `0x798c06df` | `lite::Query` |
| `liteServer.getMasterchainInfo` | `0x89b5e62e` | `lite::GetMasterchainInfo` |
| `liteServer.getTime` | `0x16ad5a34` | `lite::GetTime` |
| `liteServer.getVersion` | `0x232b940b` | `lite::GetVersion` |
| `liteServer.getAccountState` | `0x6b890e25` | `lite::GetAccountState` |
| `liteServer.getBlockProof` | `0x8aea9c44` | `lite::GetBlockProof` |
| `liteServer.masterchainInfo` | `0x85832881` | `lite::MasterchainInfo` |
| `liteServer.currentTime` | `0xe953000d` | `lite::CurrentTime` |
| `liteServer.version` | `0x5a0491e5` | `lite::Version` |
| `liteServer.accountState` | `0x7079c751` | `lite::AccountState` |
| `liteServer.error` | `0xbba9e148` | `lite::Error` |
| `liteServer.partialBlockProof` | `0x8ed0d2c1` | `lite::PartialBlockProof` |
| `liteServer.blockLinkForward` | `0x520fce1c` | `lite::BlockLink::Forward` |
| `liteServer.blockLinkBack` | `0xef7e1bef` | `lite::BlockLink::Back` |
| `liteServer.signatureSet` | `0xf644a6e6` | `lite::SignatureSet::Ordinary` |
| `liteServer.signatureSet.simplex` | `0xac249800` | `lite::SignatureSet::Simplex` |

### Signed forms (`crates/ton-net-tl/src/signed.rs`)

| TL name | Constructor id | Rust type |
|---|---|---|
| `ton.blockId` | `0xc50b6e70` | `signed::BlockId` |
| `ton.blockIdApprove` | `0x2dd44a49` | `signed::BlockIdApprove` |
| `consensus.candidateId` | `0xb691cd3f` | `signed::CandidateId` |
| `consensus.simplex.notarizeVote` | `0xcdf605a8` | `signed::Vote::Notarize` |
| `consensus.simplex.finalizeVote` | `0x40a7e105` | `signed::Vote::Finalize` |
| `consensus.candidateHashDataOrdinary` | `0xe8f9bcdc` | `signed::CandidateBlock::Ordinary` |
| `consensus.candidateHashDataEmpty` | `0x72b4d933` | `signed::CandidateBlock::Empty` |
| `consensus.dataToSign` | `0xa8e33df8` | `signed::DataToSign` |

### Bare types (no constructor id)

| TL name | Rust type | Source |
|---|---|---|
| `tonNode.blockIdExt` | `lite::BlockIdExt` | `crates/ton-net-tl/src/lite.rs` |
| `tonNode.zeroStateIdExt` | `lite::ZeroStateIdExt` | `crates/ton-net-tl/src/lite.rs` |
| `liteServer.accountId` | `lite::AccountId` | `crates/ton-net-tl/src/lite.rs` |
| `liteServer.signature` | `lite::Signature` | `crates/ton-net-tl/src/lite.rs` |

### TL primitive observed here

| TL type | Constructor id | Note |
|---|---|---|
| `Bool` (`boolTrue`) | `0x997275b5` | fixed by a hand-built `partialBlockProof` header test |

## 8. Constants reference

| Constant | Value | Meaning | Source |
|---|---|---|---|
| handshake packet size | 256 bytes | `server_key_id ++ client_pub ++ checksum ++ encrypted_params` | `crates/ton-net-adnl/src/handshake.rs` |
| handshake field sizes | 32 / 32 / 32 / 160 | the four packet fields | `crates/ton-net-adnl/src/handshake.rs` |
| handshake randomness | 192 bytes | 32-byte key seed plus 160 session parameters | `crates/ton-net-adnl/src/handshake.rs` |
| session cipher | `Ctr128BE<Aes256>` | AES-256-CTR, 128-bit big-endian counter | `crates/ton-net-adnl/src/lib.rs` |
| `rx` seed | key `params[0..32]`, iv `params[64..80]` | server-to-client cipher | `crates/ton-net-adnl/src/frame.rs` |
| `tx` seed | key `params[32..64]`, iv `params[80..96]` | client-to-server cipher | `crates/ton-net-adnl/src/frame.rs` |
| `MIN_FRAME` | 64 | smallest frame body: nonce plus checksum | `crates/ton-net-adnl/src/frame.rs` |
| `MAX_FRAME` | 16777216 (`1 << 24`) | protocol frame-body ceiling | `crates/ton-net-adnl/src/frame.rs` |
| frame checksum | `SHA-256(nonce ++ payload)` | integrity over a frame body | `crates/ton-net-adnl/src/frame.rs` |
| `CONNECT_TIMEOUT` | 10 seconds | TCP connect deadline | `crates/ton-net-adnl/src/transport.rs` |
| `MAX_FRAMES_PER_QUERY` | 8 | frames read per query before giving up | `crates/ton-net-adnl/src/connection.rs` |
| `tonNode.blockIdExt` size | 80 bytes | `4 + 8 + 4 + 32 + 32` | `crates/ton-net-tl/tests/wire.rs` |
| `getBlockProof` size | 168 with target, 88 without | `4 + 4 + 80 + 80` or `4 + 4 + 80` | `crates/ton-net-tl/tests/wire.rs` |
| `ton.blockId` size | 68 bytes | id plus two 32-byte hashes | `crates/ton-net-tl/src/signed.rs` |
| ordinary form change | masterchain block 59379986 | where mainnet moved to the simplex form | `crates/ton-net-tl/src/signed.rs`, `crates/ton-net-tl/src/lite.rs` |

## 9. Conformance vectors

The transport ships fixed public-API vectors that pin the exact bytes the handshake and
framing produce for fixed inputs, so any change to the construction is caught. They are
the construction the feasibility spike completed against a mainnet liteserver
(`crates/ton-net-adnl/tests/vectors.rs`). The fixed inputs are a real mainnet server key
`9f85439d2094b92a639c2c9493d7b740e39dea8d08b525986d39d6dd69e7f309`, a key seed of 32
`0x11` bytes, and 160 parameters where byte `i` is `(i * 3 + 5) mod 256`.

The handshake packet those inputs build, 256 bytes:

```text
5b281b7d9c4559afe95175a529ffd1b6bfb818fb73cf4ac47d7d500d8a25f9dc
d04ab232742bb4ab3a1368bd4615e4e6d0224ab71a016baf8520a332c9778737
85afab363ab509cd0ef3eaf2c68a0087b2469aeadf927ba4378c1e6f372923a0
08439a231a8ea4ff01e166f8f2f862e0eb984d63b468a261f415ff7167efa9d6
08b0cd8bcd466954506df085143e02e4f7a14967eda504a8eec41d8c0cb5dac4
e6a888cecbd76f6c7d2006540cba62aad120191af27378b1317a3e06c42498ea
27d2b44f1041407406da6c73738af0958ec1d4b70710cd7d414824b07d30ba64
7717b3c729e3e9a31b7d51c4069ebea9f12db7c980535cdbfc664251ac6c6ea9
```

The first frame sealed under the resulting `tx` cipher, over the 18-byte payload
`getMasterchainInfo` and a nonce of 32 `0x22` bytes, 86 bytes:

```text
1226b10422a78cec84bb185099587ad191f680319c0d4ac7c84041a9344ca708
944fd72c06279304de013d4e31638ced02f51083bb8e1553ee3fd91eedaee9cb
de5eb5b85168861aeda9114ae1fc6aa4984e556c3e6c
```

The read path is exercised against a live mainnet liteserver by ignored network tests that
complete a real handshake and read the masterchain head and the Elector account
(`crates/ton-net-adnl/tests/mainnet.rs`, `crates/ton-net-lite/tests/mainnet.rs`). They run
in a dedicated network CI job, not in the hermetic suite.
