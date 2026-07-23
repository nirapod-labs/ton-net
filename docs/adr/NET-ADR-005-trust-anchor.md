---
id: NET-ADR-005
title: The trust anchor, and signature-checked block sync
status: accepted
date: 2026-07-23
supersedes: none
superseded-by: none
---

# NET-ADR-005: The trust anchor, and signature-checked block sync

## Context

ton-net verifies every answer against validator signatures rather than trusting a server
(NET-ADR-001). A verifier needs a root: some block it holds true before it has checked
anything, from which every later fact is derived. That root cannot come from a server,
because a server that supplied it could then invent a chain that verifies cleanly against
it. This record fixes what the root is, where it comes from, how the client walks from it to
the network's current state, and the one freshness signal a proof cannot provide.

The root is kept as small and as explicit as the trust model allows (NET-ADR-001): a single
block, named in the network config, and the only value a verified read believes from the
chain's side of the world. Everything else is earned by cryptography.

## Decision

1. **One trusted input from the chain.** A client's root of trust is a single masterchain
   key block, taken from the network config and named `init_block`. It is the only value a
   verified read takes on trust from the chain's side of the world. Everything else a client
   believes is derived from it by cryptography, one validator signature set at a time. A
   second trusted input sits outside the chain and is the subject of point 6: the local
   clock.

2. **The anchor is always a key block.** A sync keeps a key block, never the head it proves.
   Only a key block carries the validator set that makes the next step checkable, so a chain
   can be continued only from one. The head a sync proves is handed to the read that wanted
   it and then dropped; keeping it would start the next sync from a block no chain can
   continue from. Because the anchor is always a key block, a backward link is never needed,
   and `ton-net-block` refuses one by name rather than reading and half-checking it.

3. **The pinned mainnet value.** The bundled mainnet anchor is what the public mainnet config
   published on 2026-07-21, not a block this library chose:
   - masterchain sequence number 46894135, in workchain -1 and the masterchain shard
     0x8000000000000000,
   - root hash 3048e69a12cf946ebc99b4cf9ca61c3ff4b3fcc88c4015763ac01204ecc1bf9f,
   - file hash bbdac0b4543e9141449ceb37c3c63ba6e9cc4e2c904d77f56d17e44acf1d1bed.

   A first sync starts walking from it, and the further the block recedes the longer that
   walk runs, so refreshing the bundled snapshot belongs to cutting a release rather than to
   routine upkeep.

4. **The walk.** Block sync walks a proof chain from the anchor to the network's current
   head. The server reports a head; that report is the server's word and is used only as the
   target to ask a proof toward, never believed on its own. The client asks for a proof from
   its anchor to that target, checks every link of whatever route comes back, advances the
   anchor to where the route ended, and asks again until the server calls the chain complete.
   A target that is not ahead of the anchor is refused, since a server whose head is not
   ahead has nothing to prove. A chain is accepted as complete only when it ends at the
   target the same server named a moment earlier. Each link is checked in `ton-net-block`:
   the destination header must match the identity the link claims, its key-block flag must
   match that header, and more than two thirds of the source key block's validator set must
   have signed for the destination. That per-link signature check is the load-bearing one;
   its signed form and its two-thirds threshold are fixed in NET-ADR-006.

5. **The config's two halves trust apart.** The network config carries a liteserver list and
   the anchor, and their trust requirements are opposite. The liteserver list needs none:
   every answer a server gives is checked against a proof, so a hostile server can stall or
   lie and the lie is refused. The anchor is the other case: a fetched one moves the root of
   trust to whoever served it, after which every proof verifies cleanly against whatever
   chain that party invented. Refreshing a server list and moving the anchor are therefore
   different decisions. A caller who already trusts a block, such as one saved from an
   earlier run through `Client::anchor`, hands it in through `Client::connect_from` and
   starts the walk from there.

6. **Freshness from the local clock.** A proven head older than a configured bound is
   refused. A proof establishes that a block is real and was committed by the validators and
   says nothing about when it was served, so a server can replay a genuine year-old block and
   pass every other check in the library. The block's own generation time against the local
   clock is the only freshness signal there is. The bound defaults to 600 seconds, is set by
   `Config::with_max_head_age`, and a bound of zero refuses every head by design. A block
   stamped more than 300 seconds ahead of the local clock is reported as a clock that is
   behind rather than as a fresh head, because the age measurement saturates and a clock a
   year slow would otherwise read every old block as new and switch the freshness bound off.

7. **The server does not size the client's work.** Sync is the first place a server decides
   how much work the client does, so the bounds ship with it rather than as a later pass.
   Read off the wire before any proof is parsed or any signature is verified: a reply carries
   at most 64 links, each Merkle proof within a link at most 1,048,576 bytes, and each
   signature set at most 1,024 signatures. Across a whole sync: at most 4,096 links and at
   most 512 replies. Every reply must raise the anchor, so a server that answers without
   progress ends the sync. A walk that has itself run longer than the freshness bound stops,
   because nothing it could still reach would pass the freshness check. One block-proof reply
   is held to a 60-second deadline and an ordinary read to 15 seconds. Each bound ends the
   sync with a named error, and none relaxes a check to let a sync succeed.

## Alternatives considered

- **Take the anchor from a server at startup.** Rejected. That moves the root of trust to
  the server, which is the one thing a verifier cannot let a server choose. The anchor is
  pinned in the config and refreshed when a release is cut; a caller who wants a different
  root supplies it explicitly.
- **Believe the server's reported head.** Rejected. The report carries no proof. It is used
  only as the target to walk toward, and every block on the way, the head included, is proved
  link by link or the sync fails.
- **Anchor on the last proven head instead of the last key block.** Rejected. A non-key block
  carries no validator set, so the next sync could not check its first step and would need a
  backward link to reach a key block. Keeping a key block removes that case entirely.
- **Judge freshness from the proof or the server.** Rejected. Nothing inside a proof records
  when it was served, so a replayed genuine block is indistinguishable from a current one by
  every signal except the local clock.
- **Ship the bounds later as a hardening pass.** Rejected. Sync is the first point at which a
  server can decide how much work the client does, so the bounds are part of the design.

## Consequences

- A first sync is a cold walk over every key block published since the pinned block: about
  1242 links, a couple of minutes, and roughly fifty megabytes against mainnet in July 2026,
  growing about 800 links a year while the pinned block stays fixed. A warm sync from a saved
  anchor is a link or two.
- The bundled snapshot goes stale as the pinned block recedes. Refreshing it is release work,
  and a refresh moves nobody's trust, because the value is what the network published rather
  than one this library invented.
- A caller reading many accounts syncs once and reads at the proved head rather than walking
  the chain on every read.
- The anchor a client keeps is a public block identity and holds no secret, but it is a root
  of trust. Where a caller stores it is a decision the caller's own threat model makes;
  anything that can write to that storage can choose what the client believes. The library
  stores nothing and picks no location.

## Chain scope

TON-specific. The masterchain key block, the config format's `init_block`, the proof-chain
shape, and the validator signature check are TON's. Composing several chains lives above
ton-net, in the consumer (NET-ADR-001).

## Custody and security

No user keys, no funds, no signing. The anchor and the head are public block identities, so
this record touches no custody.

The property it fixes is the trust model. One pinned masterchain key block is the only value
believed from the chain's side, and the local clock is the only other trusted input;
everything else is derived through validator-signed proof. A hostile server can stall, time
out, or answer falsely, and a false answer is refused rather than believed, because the head
it names is proved link by link and the freshness of that head is measured against the local
clock. The only way to move a client's root of trust is to change the pinned anchor or hand
in a different one, which is the caller's decision and not the library's.

## Verification

- `config.rs` tests: `Config::mainnet()` parses, names the init block at sequence number
  46894135 with the pinned root and file hashes, and the freshness bound carries its
  600-second default and can be set.
- `sync.rs` tests: a walk that does not end is stopped at the round bound; the link bound
  bites first at full replies; an anchor that does not advance ends the walk; a head past the
  bound is stale; a block ahead of the clock is reported as a clock behind rather than
  obeyed; a walk that outlasts the freshness bound stops; a zero bound refuses every head.
- `chain.rs`: `verify_chain` refuses a run that does not start at the anchor, is empty, skips
  a block, or ends anywhere other than the target; `verify_link` refuses a backward link by
  name, a link outside the masterchain, a forward link that does not move forward, a
  destination header for a different block, and a link whose signatures do not carry more
  than two thirds of the source validator set (NET-ADR-006).
- `client.rs`: `sync` refuses a target that is not ahead of the anchor and a chain called
  complete short of the target it named, and keeps the last key block of the run as the next
  anchor.
