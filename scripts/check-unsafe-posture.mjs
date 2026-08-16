// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Nirapod Labs

// Holds each crate root to the strongest unsafe-code lint it can actually carry.
//
// The six library crates set `forbid(unsafe_code)`, which the compiler enforces absolutely:
// an inner `allow` is a hard error, so nothing further is needed to keep them honest.
// The node binding cannot set it. `napi_derive` expands `#[napi]` into code carrying its
// own `#[allow(unsafe_code)]`, and `forbid` refuses to be overruled by an expansion as
// readily as by a hand-written attribute, so a binding root that forbids does not build
// at all. Eighteen errors, every one of them E0453 raised inside the macro.
//
// The binding therefore holds unsafe code, written by the macro and permitted by the
// macro, and the lint it can carry, `deny`, is exactly the one an inner allowance defeats
// without a diagnostic. So the property held there is narrower than the one the library
// crates hold, and it is stated as what is actually read: the binding's own source text
// carries no `unsafe` keyword and no allowance of that lint. A macro this repository
// defined itself could still expand to one, and nothing here would see it.
//
// Each pattern runs against probes built to trip it before the tree is read, because a
// matcher that matches nothing passes an absence check for free. That is weaker evidence
// than the second reading in `scripts/check-default-deps.mjs`, which runs over the real
// tree with the features turned on; the probes here are string literals in this file.
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

// Line comments only, and it misreads in both directions rather than one. A block comment
// quoting the literal text of an unsafe attribute is reported, which is the harmless way
// to be wrong. A `//` inside a string literal truncates the rest of that line, so an
// `unsafe` written after one on the same line is not seen, which is not harmless. Anything
// stronger needs a parser rather than a pattern.
const code = (source) => source.replace(/\/\/[^\n]*/g, "");

// Each pattern carries every shape it must match, so the reading is proved before it is
// trusted to have found nothing. `expect` sits beside `allow` because it defeats a deny
// exactly as quietly. `extern` and `static` sit beside `fn` because a reading that stops
// at `fn` walks straight past `unsafe extern "C" fn`, which is the shape a hand-written
// N-API export takes, and this is the one crate where somebody would write one.
const HAND_WRITTEN = [
  {
    what: "an allowance of the unsafe-code lint",
    pattern: /#!?\[\s*(?:allow|expect)\s*\([^)]*\bunsafe_code\b/,
    probes: ["#[allow(unsafe_code)]", "#![expect(unsafe_code)]", "#[allow(dead_code, unsafe_code)]"],
  },
  {
    what: "an unsafe block, function, external item, implementation, trait or static",
    pattern: /\bunsafe\s*(?:\{|fn\b|extern\b|impl\b|trait\b|static\b)/,
    probes: [
      "unsafe { }",
      "unsafe fn f() {}",
      'unsafe extern "C" fn f() {}',
      "unsafe impl Send for T {}",
      "unsafe trait T {}",
      "unsafe static mut X: u8 = 0;",
    ],
  },
];

const problems = [];

// Run first: a pattern that cannot find its own probe proves nothing about a tree it goes
// on to report clean. The attribute readings below carry no probe because each asserts a
// presence rather than an absence, and a presence check that reads nothing fails loudly.
for (const { what, pattern, probes } of HAND_WRITTEN) {
  for (const probe of probes) {
    if (!pattern.test(probe)) {
      problems.push(`the reading for ${what} does not match \`${probe}\`, so it proves nothing`);
    }
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
  `${FORBIDS.length} library crate root(s) forbid unsafe code; ${sources.length} binding source file(s) carry no unsafe keyword and no allowance of the lint`,
);
