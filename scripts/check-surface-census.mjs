// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Nirapod Labs

// Counts stated in prose, against the thing they count.
//
// A sentence that counts something in this tree is a census, and a census in prose
// is written from a search that covered part of what the sentence then claims. The
// failure does not look like one at the time: the code was read, the search was
// correct, and the sentence offered as its conclusion is simply wider than the
// search was. It goes wrong later as well, without anyone touching the sentence,
// when the set it counts moves in a commit that has no reason to open the document
// doing the counting.
//
// Nothing else here reads for that. rustdoc checks that a link resolves, not that a
// list beside it is complete. The test suite compiles the examples a document carries
// and not the sentences around them. `typos` reads spelling. So a document can name a type the
// facade stopped exporting several releases ago, or count features a crate no longer
// has, and every gate stays green while a consumer reads the wrong number.
//
// Two counts in this tree have a machine-readable answer, and those are the two here:
//
//   1. the re-export list in docs/api-design.md against core/src/lib.rs, which is the
//      surface a consumer imports, and
//   2. a prose count of a crate's Cargo features, in tracked markdown or in a
//      comment, against the features that crate's manifest declares.
//
//   node scripts/check-surface-census.mjs
//
// A third was considered and is deliberately absent: flagging a repository-scope
// quantifier ("the only", "every", "no ... anywhere") bound to a repository-scope
// noun in a commit message, and refusing until the author names the command behind
// it. Three things rule it out. The quantifier is not the defect. The defect is the
// distance between what a command covered and what the sentence says, and a matcher
// over prose sees neither half, so it would fire on sentences it cannot judge and be
// silent on the ones it should. The remedy is a token an author appends, and a check
// of that shape has already been satisfied here by appending one, which leaves a
// green check standing over a claim that is still wrong and spends the reviewer
// attention that did catch every instance of this. And a commit message is not in the
// tree this gate reads. What is left is the class above: a count whose answer is
// mechanical, compared against it.

import { execFileSync } from "node:child_process";
import { existsSync, readFileSync } from "node:fs";
import { dirname, join, relative } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
const root = join(here, "..");

const failures = [];
const summary = [];

/** Every workspace member, with the features cargo resolved for it. */
function workspaceCrates() {
  const meta = JSON.parse(
    execFileSync("cargo", ["metadata", "--no-deps", "--format-version", "1"], {
      cwd: root,
      encoding: "utf8",
      maxBuffer: 32 * 1024 * 1024,
    }),
  );
  return meta.packages.map((pkg) => ({
    name: pkg.name,
    dir: relative(root, dirname(pkg.manifest_path)),
    // `default` names a set of the others rather than a fourth thing, so a count of
    // what a caller can turn on does not include it. Read through cargo rather than
    // scanned out of `[features]`, because an optional dependency declared without
    // the `dep:` spelling creates a feature that never appears in that table, and a
    // scanner would report a crate as having fewer features than it has.
    features: Object.keys(pkg.features).filter((name) => name !== "default"),
  }));
}

const crates = workspaceCrates();
if (crates.length === 0) {
  console.error("cargo metadata reported no workspace members");
  process.exit(1);
}

// ---------------------------------------------------------------------------
// 1. The facade's re-export list against the document that enumerates it.
// ---------------------------------------------------------------------------

// The facade is the whole import surface: a consumer depends on one crate and can
// reach exactly what this file makes public. The document that describes the API
// writes that surface out as a list of names, so the list and the file are two copies
// of one set and only one of them is compiled. Other documents mention a type in
// passing; this is the one place checked, because a list is a census and a mention
// is not.
const FACADE_SOURCE = "core/src/lib.rs";
const FACADE_DOC = "docs/api-design.md";
const FACADE_ANCHOR = "The re-exported surface";

const facadeText = readFileSync(join(root, FACADE_SOURCE), "utf8");

/** The names one `pub use` item puts at the crate root. */
function reExportedNames(item) {
  const braced = item.match(/\{([\s\S]*)\}/);
  const parts = braced ? braced[1].split(",") : [item];
  const names = [];
  for (const part of parts) {
    const trimmed = part.trim();
    if (trimmed.length === 0) {
      continue;
    }
    const alias = trimmed.match(/\bas\s+([A-Za-z_][A-Za-z0-9_]*)\s*$/);
    const name = alias ? alias[1] : trimmed.split("::").pop().trim();
    if (/^[A-Za-z_][A-Za-z0-9_]*$/.test(name) && name !== "self") {
      names.push(name);
    }
  }
  return names;
}

const exported = new Set();
for (const match of facadeText.matchAll(/^pub use\s+([\s\S]*?);/gm)) {
  const item = match[1];
  // A glob re-export has no enumerable answer here: what it exports is whatever the
  // other crate exports today. There is no such use in the facade, and the facade is
  // the one place where a closed surface is the point, so this refuses rather than
  // reports a set it cannot know.
  if (item.includes("*")) {
    failures.push(
      `${FACADE_SOURCE} re-exports with a glob (\`${item.trim()}\`), so its surface ` +
        "cannot be enumerated and no document can be checked against it",
    );
    continue;
  }
  for (const name of reExportedNames(item)) {
    exported.add(name);
  }
}
// Items the facade defines itself and makes public, which a consumer imports from the
// same place and the document lists in the same list.
for (const match of facadeText.matchAll(
  /^pub\s+(?:const|static|fn|struct|enum|trait|type|union|mod)\s+([A-Za-z_][A-Za-z0-9_]*)/gm,
)) {
  exported.add(match[1]);
}

const docLines = readFileSync(join(root, FACADE_DOC), "utf8").split("\n");
const anchorIndex = docLines.findIndex((line) => line.includes(FACADE_ANCHOR));
if (anchorIndex < 0) {
  // The list is found by the sentence that introduces it. If that sentence is
  // reworded the list is still there and still able to drift, so this fails loudly
  // rather than passing over a document it can no longer find its way around.
  console.error(
    `no "${FACADE_ANCHOR}" in ${FACADE_DOC}, so the re-export list cannot be located; ` +
      "the list still exists and still drifts, so point this at it rather than removing it",
  );
  process.exit(1);
}

let cursor = anchorIndex + 1;
while (cursor < docLines.length && docLines[cursor].trim() === "") {
  cursor += 1;
}
const listStart = cursor;
const listLines = [];
while (cursor < docLines.length && docLines[cursor].trim() !== "") {
  listLines.push(docLines[cursor]);
  cursor += 1;
}
if (!listLines.some((line) => line.trimStart().startsWith("-"))) {
  console.error(
    `the block after "${FACADE_ANCHOR}" in ${FACADE_DOC}:${listStart + 1} is not a list`,
  );
  process.exit(1);
}

// Every backticked identifier in the list. A backticked name that is not a plain Rust
// identifier, such as a crate name with hyphens, is prose about where the types come
// from rather than one of the names, and drops out here. Which group a name is listed
// under is not checked: the groups are named in prose ("the block layer") rather than
// by crate, and reading a crate out of that phrase would be inventing a mapping.
const documented = new Set();
for (const match of listLines.join("\n").matchAll(/`([^`]+)`/g)) {
  if (/^[A-Za-z_][A-Za-z0-9_]*$/.test(match[1])) {
    documented.add(match[1]);
  }
}

const missingFromDoc = [...exported].filter((name) => !documented.has(name)).sort();
const missingFromCode = [...documented].filter((name) => !exported.has(name)).sort();

for (const name of missingFromDoc) {
  failures.push(
    `${FACADE_SOURCE} exports \`${name}\`, and the list in ` +
      `${FACADE_DOC}:${listStart + 1} does not name it`,
  );
}
for (const name of missingFromCode) {
  failures.push(
    `${FACADE_DOC}:${listStart + 1} lists \`${name}\`, and ${FACADE_SOURCE} does not export it`,
  );
}
summary.push(`${exported.size} name(s) on the facade, all of them in ${FACADE_DOC}`);

// ---------------------------------------------------------------------------
// 2. A prose count of a crate's features against its manifest.
// ---------------------------------------------------------------------------

// A feature count is the cheapest census to get wrong, because a feature is added in
// the crate that gains it and counted in prose somewhere else. This looks for a count
// that quantifies the word itself, "the two cell-engine features", and compares it
// against what cargo says that crate declares.
//
// Precision is chosen over reach, because a check that fires on prose it cannot judge
// costs more than it saves. Three conditions have to hold together, and a sentence
// missing any of them is left alone even though it may be counting features:
//
//   - the count stands directly in front of the word, with at most three modifiers
//     between them and no function word or verb among those modifiers, so "one
//     dependency enters the tree under the feature" is not a count of features;
//   - the sentence resolves to one crate, by naming it among those modifiers, by
//     naming it in full in the same paragraph, or by sitting in that crate's own
//     directory; and
//   - the paragraph carries a Cargo cue, unless a modifier already named the crate.
//     Without one, "the two features of a BoC header" is the ordinary English word
//     and not a claim about a manifest.
//
// Decision records are skipped for the reason check-versions skips them: a record
// states a count as it stood when the decision was taken, which is history rather
// than a description of this build. So are the generated notices, which are not this
// repository's prose at all.

const COUNT_WORDS = new Map([
  ["two", 2],
  ["three", 3],
  ["four", 4],
  ["five", 5],
  ["six", 6],
  ["seven", 7],
  ["eight", 8],
  ["nine", 9],
  ["ten", 10],
  ["eleven", 11],
  ["twelve", 12],
]);

const COUNT_PHRASE = new RegExp(
  String.raw`(?<![\w-])(${[...COUNT_WORDS.keys()].join("|")}|\d{1,2})\s+` +
    String.raw`((?:[A-Za-z][A-Za-z0-9_-]*\s+){0,3})features(?![\w-])`,
  "gi",
);

// Words that turn the span into a clause rather than a noun phrase. "two crates
// declare features" counts crates, not features.
const NOT_A_MODIFIER = new Set([
  "a", "an", "and", "are", "as", "at", "be", "been", "both", "but", "by", "can", "carries",
  "carry", "declare", "declared", "declares", "for", "from", "gain", "gained", "gains", "had",
  "has", "have", "in", "is", "it", "its", "more", "no", "not", "of", "on", "or", "other",
  "our", "own", "same", "such", "than", "that", "the", "their", "then", "these", "they",
  "this", "those", "to", "under", "use", "used", "uses", "was", "were", "which", "with",
]);

const CARGO_CUES = [
  /\bcargo\b/i,
  /--features\b/,
  /\[features\]/,
  /\bfeature[\s-]gated?\b/i,
  /\bfeature[\s-]flags?\b/i,
  /\bdefault build\b/i,
  /\bdefault feature/i,
  /\bopt-in\b/i,
  /\boptional\b/i,
  /\bmanifest\b/i,
];

for (const crate of crates) {
  crate.aliases = new Set([crate.name, crate.name.replaceAll("-", "_")]);
  const tail = crate.name.split("-").pop();
  if (tail.length > 2) {
    crate.aliases.add(tail);
  }
  crate.named = new RegExp(String.raw`(?<![\w-])${crate.name}(?![\w-])`);
}

// The library and the crate at its front carry one name, so that name in a paragraph
// is as likely to be the project as the crate: every crate's own header opens by
// saying which library it belongs to. It stays a strong signal when it stands beside
// the word being counted, and it is dropped as evidence at paragraph range, where a
// crate's own directory says more about what the count is about. Which name that is
// comes from the workspace rather than a constant: the one every other name extends.
// The trade is that a count of that crate's own features, made from a document no
// crate owns, is reached only when the name stands beside the word.
const umbrella = crates.reduce((a, b) => (a.name.length <= b.name.length ? a : b));
const umbrellaIsPrefix = crates.every(
  (crate) => crate === umbrella || crate.name.startsWith(`${umbrella.name}-`),
);

/** Which crate a count is about, and whether the prose said so beside the word. */
function resolveCrate(modifiers, paragraph, rel) {
  for (const token of modifiers) {
    for (const part of token.toLowerCase().split(/[-_]/)) {
      const hit = crates.find((crate) => crate.aliases.has(part));
      if (hit) {
        return { crate: hit, byName: true };
      }
    }
  }
  const named = crates.filter(
    (crate) =>
      crate.named.test(paragraph) && !(umbrellaIsPrefix && crate === umbrella),
  );
  if (named.length === 1) {
    return { crate: named[0], byName: false };
  }
  // A crate's own README and its own sources are about that crate, so a count in one
  // needs no name to be attached to the right manifest.
  const owner = crates.find((crate) => crate.dir.length > 0 && rel.startsWith(`${crate.dir}/`));
  if (owner) {
    return { crate: owner, byName: false };
  }
  return null;
}

/** Paragraphs of prose, each with the line it starts on, offsets preserved. */
function proseBlocks(rel, text) {
  const lines = text.split("\n");
  const blocks = [];
  let current = null;
  let fenced = false;

  const flush = () => {
    if (current && current.lines.length > 0) {
      blocks.push({ line: current.line, text: current.lines.join("\n") });
    }
    current = null;
  };

  lines.forEach((line, index) => {
    if (rel.endsWith(".md")) {
      // A fenced block is a command or a snippet. A count inside one is code.
      if (line.trimStart().startsWith("```")) {
        fenced = !fenced;
        flush();
        return;
      }
      if (fenced || line.trim() === "") {
        flush();
        return;
      }
    } else if (!line.trimStart().startsWith("//")) {
      // Outside markdown only comments are prose. The argument for a check is written
      // beside it here as often in a plain `//` header as in a `///` one, so both
      // count and restricting this to doc comments would skip where the sentences are.
      flush();
      return;
    }
    if (current === null) {
      current = { line: index + 1, lines: [] };
    }
    current.lines.push(line);
  });
  flush();
  return blocks;
}

const tracked = execFileSync("git", ["ls-files", "*.md", "*.rs"], {
  cwd: root,
  encoding: "utf8",
})
  .split("\n")
  .filter(
    (rel) =>
      rel.length > 0 && !rel.startsWith("docs/adr/") && rel !== "THIRD-PARTY-LICENSES.md",
  );

let counted = 0;
for (const rel of tracked) {
  const path = join(root, rel);
  if (!existsSync(path)) {
    continue;
  }
  for (const block of proseBlocks(rel, readFileSync(path, "utf8"))) {
    for (const match of block.text.matchAll(COUNT_PHRASE)) {
      const word = match[1].toLowerCase();
      const stated = COUNT_WORDS.get(word) ?? Number(word);
      const modifiers = match[2].trim().length > 0 ? match[2].trim().split(/\s+/) : [];
      if (modifiers.some((token) => NOT_A_MODIFIER.has(token.toLowerCase()))) {
        continue;
      }
      const resolved = resolveCrate(modifiers, block.text, rel);
      if (resolved === null) {
        continue;
      }
      const { crate, byName } = resolved;
      const backticked = [...block.text.matchAll(/`([^`]+)`/g)].map((m) => m[1]);
      const cued =
        byName ||
        crate.named.test(block.text) ||
        backticked.some((name) => crate.features.includes(name)) ||
        CARGO_CUES.some((cue) => cue.test(block.text));
      if (!cued) {
        continue;
      }
      counted += 1;
      if (stated === crate.features.length) {
        continue;
      }
      const line = block.line + (block.text.slice(0, match.index).match(/\n/g)?.length ?? 0);
      const declared =
        crate.features.length === 0
          ? "declares none"
          : `declares ${crate.features.length}: ${crate.features.join(", ")}`;
      failures.push(
        `${rel}:${line} counts ${stated} feature(s) of ${crate.name}, whose manifest ${declared}`,
      );
    }
  }
}
summary.push(`${counted} feature count(s) in prose, each matching its manifest`);

if (failures.length > 0) {
  console.error("a stated count disagrees with what it counts:");
  for (const line of failures) {
    console.error(`  - ${line}`);
  }
  console.error(
    "the code is the count; a document that states a number states the one the tree holds",
  );
  process.exit(1);
}

console.log(summary.join("; "));
