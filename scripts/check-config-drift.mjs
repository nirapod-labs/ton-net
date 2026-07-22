// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Nirapod Labs

// Whether the bundled mainnet configuration still matches the published one.
//
// The snapshot test reports two numbers that decay, and only one of them is
// something this repository can act on. How many bundled liteservers answer is
// the network's business. How far the pinned block sits behind the head is not
// drift in this copy at all: the pinned block is the one TON publishes, TON
// rotates it rarely, and a lag of tens of millions of blocks is the age of the
// upstream anchor rather than a stale file here. Reading that lag as decay leads
// to a refresh that copies the same bytes back.
//
// What a refresh actually fixes is a difference between the two files, and this
// is what says whether there is one. It compares the fields a caller depends on:
// the init block that is the default trust anchor, the zero state, the hardforks,
// and the liteserver set. Key order and formatting are ignored, because neither
// reaches a caller.
//
//   node scripts/check-config-drift.mjs
//
// Reaches the network, so it is not part of the hermetic gate. A refresh moves
// the default trust anchor, so `just test-sync` has to run after one, not before.

import { readFileSync } from "node:fs";

const PUBLISHED = "https://ton.org/global.config.json";
const BUNDLED = "crates/ton-net/src/mainnet.config.json";

// `shard` is -2^63, which no JSON parser in JavaScript keeps exactly. Both sides
// are read the same way and lose the same digits, so comparing them still answers
// the question asked here. Nothing else in this file is near the safe range.
const server = (s) => `${s.ip}:${s.port}:${s.id.key}`;
const same = (a, b) => JSON.stringify(a) === JSON.stringify(b);

const bundled = JSON.parse(readFileSync(BUNDLED, "utf8"));

let published;
try {
  const response = await fetch(PUBLISHED, { signal: AbortSignal.timeout(30_000) });
  if (!response.ok) throw new Error(`HTTP ${response.status}`);
  published = await response.json();
} catch (cause) {
  // An unreachable registry is not a drifting config, and reporting it as one
  // would send somebody to refresh a file that may be current.
  console.error(`could not read ${PUBLISHED}: ${cause.message}`);
  process.exit(2);
}

const drift = [];

for (const field of ["init_block", "zero_state", "hardforks"]) {
  if (!same(published.validator?.[field], bundled.validator?.[field])) {
    drift.push(
      `validator.${field} differs\n` +
        `  published: ${JSON.stringify(published.validator?.[field])}\n` +
        `  bundled:   ${JSON.stringify(bundled.validator?.[field])}`,
    );
  }
}

const up = new Set(published.liteservers.map(server));
const mine = new Set(bundled.liteservers.map(server));
const added = [...up].filter((s) => !mine.has(s));
const dropped = [...mine].filter((s) => !up.has(s));

for (const s of added) drift.push(`liteserver published but not bundled: ${s}`);
for (const s of dropped) drift.push(`liteserver bundled but not published: ${s}`);

if (drift.length > 0) {
  console.error(drift.join("\n"));
  console.error(
    `\n${drift.length} difference(s). Refreshing means taking the published ` +
      `configuration into ${BUNDLED}. If the init block moved, that moves the ` +
      `default trust anchor, so run the walk from the new one before releasing: ` +
      `just test-sync`,
  );
  process.exit(1);
}

console.log(
  `bundled configuration matches the published one: same init block at seqno ` +
    `${bundled.validator.init_block.seqno}, same zero state and hardforks, ` +
    `same ${mine.size} liteservers`,
);
