// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Nirapod Labs

// Holds the library's layers to the one direction they are allowed to run in.
//
// The layering used to be a crate graph, on the theory that a crate declaring no
// dependency on the transport could not reach it. That theory was never true, and the
// reason is invisible in every manifest: `std` needs no dependency edge. A
// `std::net::TcpStream` opened inside the block crate compiled with nothing to change and
// nothing to notice, and a `tokio.workspace = true` added to the same manifest passed the
// whole gate in silence. Reading the source text is strictly stronger than reading the
// graph, because the socket, the filesystem, the process, the environment, a thread and
// the clock all arrive through `std`, and a graph can see none of them.
//
// The direction. The cell engine, the typed structures, the proof engine and the TL codec
// decide over bytes already in hand. None of them may name the transport above it
// (`adnl`, `lite`, `client`), name tokio or getrandom, or reach the socket, the
// filesystem, the process, the environment, a thread or the clock. Three module names
// rather than five: `sync` and `send` live under `client`, so refusing the parent refuses
// them with it. `lite` sits above the wire and below the cells, and it may not name `cell`
// either, because a liteserver answer leaves that layer as the bytes it arrived as and is
// opened above it.
//
// The absence is read twice, and the second reading is the only thing that makes the
// first one mean anything. A matcher that matches nothing passes an absence check for
// free, so the same reading has to find the edges that are supposed to be present, `tlb`
// reaching `cell` and `proof` reaching both. A pattern that has quietly stopped matching
// reports itself broken instead of reporting the tree clean.
//
// One reach is permitted rather than absent, and it is named here rather than left as a
// hole in the pattern. `std::thread` stays available under `core/src/cell/boc/`, where
// splitting a finalization wave across scoped threads is a capability with its own
// `parallel` feature. Refusing it there would refuse the feature.
//
// One reach is deliberately not read at all. `HashMap` and `HashSet` are how randomness
// actually arrives in the cell engine: the standard library's default hasher seeds
// `RandomState` from the operating system on first use, at eighteen source lines under
// `core/src/cell/`. All eighteen are legitimate, and reporting them to catch a property
// nobody is attacking is the kind of noise that gets a check switched off inside a
// release. The reach is real, and it is named rather than closed.
//
//   node scripts/check-layers.mjs

import { execFileSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");

// What each layer may not name, with the reason, so a failure explains itself without
// anyone having to rediscover which way the arrows point.
const DECIDES_WITHOUT = [
  ["crate::adnl", "the transport sits above this layer"],
  ["crate::lite", "the query wire sits above this layer"],
  ["crate::client", "the facade sits above this layer, and `sync` and `send` sit under it"],
  ["tokio", "a layer that decides over bytes already in hand holds no runtime"],
  ["getrandom", "the per-session randomness is drawn at the I/O edge and nowhere else"],
  ["std::net", "the socket belongs to the transport"],
  ["std::fs", "nothing down here reads a file"],
  ["std::process", "nothing down here starts or inspects a process"],
  ["std::env", "a decision that reads the environment is not the same decision twice"],
  ["std::thread", "a decision over bytes in hand needs no thread of its own"],
  ["std::time::SystemTime", "a wall clock is an input from outside, and proofs do not take one"],
  ["std::time::Instant", "a deadline belongs to the caller that set it"],
];

// The four layers that decide, each read as its directory and the module body beside it.
// Naming them individually rather than globbing `core/src` is deliberate: a new module
// there should stay uncovered until somebody decides which side of the line it is on.
const DECIDING = ["cell", "tlb", "proof", "tl"];

// `lite` frames queries and reads answers back. Its own module documentation is the claim
// this refusal holds it to: a read comes back as a `ServerReported` value carrying its
// proof bytes untouched, so the cells inside one are opened above this layer.
const WIRE = "lite";
const WIRE_DECIDES_WITHOUT = [["crate::cell", "an answer leaves this layer as the bytes it arrived as"]];

// The one permitted reach, as a path and the prefix it is permitted under. The threaded
// finalization wave is what the `parallel` feature buys, so the capability is the point of
// that code rather than a leak into it.
const PERMITTED = [["std::thread", "core/src/cell/boc/"]];

// The edges that are supposed to be there, read by the same patterns as the absences
// above. These are what stand between a silent no-op and a passing gate.
const PRESENT = [
  ["tlb", "crate::cell"],
  ["proof", "crate::cell"],
  ["proof", "crate::tlb"],
];

// A Rust path as it is actually written, `std::time::Instant` and the braced form
// `std::time::{Duration, Instant}` that names the same thing. Splitting at the last `::`
// and admitting a brace group between the halves reads both. Only the final segment is
// read out of a brace group, so `use std::{fs, net}` is caught and a deeper nesting such
// as `use std::{time::Instant}` is not; an unterminated group can also carry the match
// further than one import. Both errors report something rather than miss it, which is the
// harmless direction. Anything stronger needs a parser rather than a pattern.
const reach = (path) => {
  const cut = path.lastIndexOf("::");
  if (cut < 0) {
    return new RegExp(String.raw`\b${path}\b`);
  }
  const parent = path.slice(0, cut);
  const leaf = path.slice(cut + 2);
  return new RegExp(String.raw`\b${parent}::(?:\{[^}]*\b)?${leaf}\b`);
};

// The shapes each refusal has to match, generated from the path rather than listed by
// hand, so a refusal added to the tables above cannot arrive unprobed.
const probesFor = (path) => {
  const cut = path.lastIndexOf("::");
  if (cut < 0) {
    return [`use ${path}::thing;`, `${path}::thing()`];
  }
  return [
    `use ${path};`,
    `use ${path}::thing;`,
    `use ${path.slice(0, cut)}::{other, ${path.slice(cut + 2)}};`,
  ];
};

// Line comments only, and it misreads in both directions rather than one. A block comment
// quoting the literal text of a refused path is reported, which is the harmless way to be
// wrong. A `//` inside a string literal truncates the rest of that line, so a reach
// written after one on the same line is not seen, which is not harmless. Documentation
// comments go with the rest: `[crate::tlb]` written in prose about a module is a sentence,
// not a dependency, and reading it as one would make the present-edge assertions below
// satisfiable by prose.
const code = (source) => source.replace(/\/\/[^\n]*/g, "");

// Only the sources a person edits. `git ls-files` keeps a build artefact under target/ and
// anything untracked out of the reading.
const sources = (module) =>
  execFileSync("git", ["ls-files", `core/src/${module}`, `core/src/${module}.rs`], {
    cwd: root,
    encoding: "utf8",
  })
    .split("\n")
    .filter((rel) => rel.endsWith(".rs"));

const permitted = (path, rel) =>
  PERMITTED.some(([allowed, prefix]) => allowed === path && rel.startsWith(prefix));

const problems = [];

// Run first: a pattern that cannot find its own probe proves nothing about a tree it goes
// on to report clean.
for (const [path] of [...DECIDES_WITHOUT, ...WIRE_DECIDES_WITHOUT]) {
  for (const probe of probesFor(path)) {
    if (!reach(path).test(probe)) {
      problems.push(`the reading for ${path} does not match \`${probe}\`, so it proves nothing`);
    }
  }
}

const read = new Map();

for (const module of [...DECIDING, WIRE]) {
  const files = sources(module);
  if (files.length === 0) {
    problems.push(`no sources were listed for ${module}, so the readings below ran over nothing`);
  }
  read.set(
    module,
    files.map((rel) => [rel, code(readFileSync(join(root, rel), "utf8"))]),
  );
}

const refuse = (module, table) => {
  for (const [rel, body] of read.get(module)) {
    for (const [path, why] of table) {
      if (!permitted(path, rel) && reach(path).test(body)) {
        problems.push(`${rel} reaches ${path}, and ${why}`);
      }
    }
  }
};

for (const module of DECIDING) {
  refuse(module, DECIDES_WITHOUT);
}
refuse(WIRE, WIRE_DECIDES_WITHOUT);

for (const [module, path] of PRESENT) {
  const found = read.get(module).some(([, body]) => reach(path).test(body));
  if (!found) {
    problems.push(
      `${module} no longer reaches ${path}, so every absence reported above was read by a pattern that finds nothing`,
    );
  }
}

if (problems.length > 0) {
  console.error("the layers do not run the way the tree claims:");
  for (const line of problems) {
    console.error(`  - ${line}`);
  }
  process.exit(1);
}

const counted = [...read.values()].reduce((total, files) => total + files.length, 0);

console.error(
  `${counted} source file(s) across ${read.size} layer(s) name nothing above them; the ${PRESENT.length} edge(s) below them are still there`,
);
