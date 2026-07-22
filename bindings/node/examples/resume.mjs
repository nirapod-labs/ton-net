// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Nirapod Labs

// Saves the block a walk ended on, so the next run does not walk again.
//
//   node examples/resume.mjs     # first run walks
//   node examples/resume.mjs     # second run does not
//
// A first sync checks every key block published since the pinned one, which is over a
// thousand links. A client that keeps the block it finished on hands that back and pays
// one.
//
// Note what the anchor is worth: everything this client goes on to believe is derived
// from it, so whatever can write to the file below can choose what the client trusts.
// A world-writable temp file is the wrong place for it in anything real.

import { readFileSync, writeFileSync } from "node:fs";
import { Config, TonClient } from "ton-net";

const SAVED = "anchor.json";

// `shard` and `lastTransLt` cross the boundary as strings because they are 64-bit and a
// JavaScript number is not, and the hashes cross as Buffers. Neither survives JSON on
// its own, so both are converted rather than assumed.
function load() {
  try {
    const saved = JSON.parse(readFileSync(SAVED, "utf8"));
    return {
      workchain: saved.workchain,
      shard: saved.shard,
      seqno: saved.seqno,
      rootHash: Buffer.from(saved.rootHash, "hex"),
      fileHash: Buffer.from(saved.fileHash, "hex"),
    };
  } catch {
    return null;
  }
}

function save(anchor) {
  writeFileSync(
    SAVED,
    `${JSON.stringify(
      {
        workchain: anchor.workchain,
        shard: anchor.shard,
        seqno: anchor.seqno,
        rootHash: anchor.rootHash.toString("hex"),
        fileHash: anchor.fileHash.toString("hex"),
      },
      null,
      2,
    )}\n`,
  );
}

const config = Config.mainnet();
const anchor = load();

const client = anchor
  ? await TonClient.connectFrom(config, anchor)
  : await TonClient.connect(config);
console.log(
  anchor
    ? `resuming from block ${anchor.seqno}`
    : "no saved anchor, walking from the block the config pins",
);

const report = await client.sync();
console.log(`${report.links} links this time, head ${report.head.seqno}`);

const elector =
  "-1:3333333333333333333333333333333333333333333333333333333333333333";
console.log("balance", (await client.account(elector)).value.balance);

// The client keeps a key block behind the head rather than the head itself, so the next
// walk has something a chain can continue from.
const next = await client.anchor();
if (next) {
  save(next);
  console.log(`saved block ${next.seqno} for next time`);
}
