// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Nirapod Labs

// Holds each crate root to the strongest unsafe-code lint it can actually carry.
//
// The six core crates set `forbid(unsafe_code)`, which the compiler enforces absolutely:
// an inner `allow` is a hard error, so nothing further is needed to keep them honest.
// The node binding cannot set it. `napi_derive` expands `#[napi]` into code carrying its
// own `#[allow(unsafe_code)]`, and `forbid` refuses to be overruled by an expansion as
// readily as by a hand-written attribute, so a binding root that forbids does not build
// at all. Eighteen errors, every one of them E0453 raised inside the macro.
//
// Two facts follow from that, and the second is why this file exists. The binding
// contains unsafe code, written by the macro and permitted by the macro. And the lint it
// can carry, `deny`, is exactly the one an inner `allow` defeats without a diagnostic.
// So the property worth holding there is narrower than the one the core crates hold, and
// it has to be stated as what it is: no unsafe code that a person wrote, as opposed to
// none at all.
//
// The absence is read twice. A matcher that matches nothing passes an absence check for
// free, so each pattern is also run against a probe built to trip it, and a pattern that
// fails to match its own probe is reported as a broken reading rather than a clean tree.
// That discipline is copied from `scripts/check-default-deps.mjs`.
//
//   node scripts/check-unsafe-posture.mjs

import { execFileSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");

// A crate root that decodes bytes from a peer, each of which forbids outright. Naming
// them individually rather than globbing is deliberate: a new core crate should fail
// this list until somebody decides which posture it carries.
const FORBIDS = [
  "crates/ton-net/src/lib.rs",
  "crates/ton-net-adnl/src/lib.rs",
  "crates/ton-net-block/src/lib.rs",
  "crates/ton-net-cell/src/lib.rs",
  "crates/ton-net-lite/src/lib.rs",
  "crates/ton-net-tl/src/lib.rs",
];

// A crate root that cannot forbid, with the reason, so a failure explains itself without
// anyone having to rediscover the macro expansion.
const DENIES = [["bindings/node/src/lib.rs", "napi_derive expands an inner allow"]];

// Rust has no block-comment nesting rule that a regex handles well, so only line comments
// are stripped. A block comment holding the literal text of an unsafe attribute would be
// reported; that is the direction to err in.
const code = (source) => source.replace(/\/\/[^\n]*/g, "");

// Each pattern carries the text it must match, so the reading is proved before it is
// trusted to have found nothing.
const HAND_WRITTEN = [
  {
    what: "an allow of the unsafe-code lint",
    pattern: /#!?\[\s*allow\s*\([^)]*\bunsafe_code\b/,
    probe: "#[allow(unsafe_code)]",
  },
  {
    what: "an unsafe block, function, implementation or trait",
    pattern: /\bunsafe\s*(\{|fn\b|impl\b|trait\b)/,
    probe: "unsafe { }",
  },
];

const problems = [];

// Reading two, run first: a pattern that cannot find its own probe proves nothing about a
// tree it reports clean.
for (const { what, pattern, probe } of HAND_WRITTEN) {
  if (!pattern.test(probe)) {
    problems.push(`the reading for ${what} does not match its own probe, so it proves nothing`);
  }
}

const attribute = (rel, level) =>
  new RegExp(String.raw`^#!\[${level}\(unsafe_code\)\]`, "m").test(
    readFileSync(join(root, rel), "utf8"),
  );

for (const rel of FORBIDS) {
  if (!attribute(rel, "forbid")) {
    problems.push(`${rel} does not forbid unsafe code, and a crate that decodes peer bytes must`);
  }
}

for (const [rel, why] of DENIES) {
  if (attribute(rel, "forbid")) {
    problems.push(`${rel} forbids unsafe code, which does not build here: ${why}`);
  } else if (!attribute(rel, "deny")) {
    problems.push(`${rel} neither forbids nor denies unsafe code`);
  }
}

// Only the sources a person edits. A generated file under target/ is not in git, and the
// macro's own expansion never appears here, which is the whole point of reading the text
// rather than the built artifact.
const sources = execFileSync("git", ["ls-files", "bindings/*/src/*.rs", "bindings/*/src/**/*.rs"], {
  cwd: root,
  encoding: "utf8",
})
  .split("\n")
  .filter((rel) => rel.length > 0);

if (sources.length === 0) {
  problems.push("no binding sources were listed, so the absence below was read over nothing");
}

for (const rel of sources) {
  const body = code(readFileSync(join(root, rel), "utf8"));
  for (const { what, pattern } of HAND_WRITTEN) {
    if (pattern.test(body)) {
      problems.push(`${rel} carries ${what}, which the binding's deny cannot refuse on its own`);
    }
  }
}

if (problems.length > 0) {
  console.error("the unsafe-code posture is not what the tree claims:");
  for (const line of problems) {
    console.error(`  - ${line}`);
  }
  process.exit(1);
}

console.error(
  `${FORBIDS.length} crate root(s) forbid unsafe code; ${sources.length} binding source(s) carry none a person wrote`,
);
