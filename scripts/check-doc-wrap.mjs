// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Nirapod Labs

// Catches a documentation paragraph that was edited without being reflowed.
//
// The defect is invisible to every tool already in the gate and it arrives from a
// predictable place: a sentence gets rewritten in answer to a review, the replacement is a
// different length from what it replaced, and the line breaks around it stay where the old
// text put them. What lands is a paragraph with a short line in the middle of it, or one
// line running well past its neighbours. Neither is wrong, so nothing fails, and what a
// reader sees in `git blame` is prose patched in without being read back.
//
// rustfmt would do this, and cannot be asked to: `wrap_comments` is nightly-only, and
// `rustfmt.toml` excludes nightly keys on the stated ground that a nightly-only key warns on
// every run for every contributor, which trains people to ignore the output. That reasoning
// holds, so the check is written here instead, in the shape `check-layers.mjs` already uses
// for this repository's own rules.
//
// The predicate is greedy wrapping rather than a width. A fixed threshold cannot work: doc
// blocks in this tree fill anywhere from the high seventies to ninety-nine, so any constant
// is either blind in one file or noise in another. What is read instead is the block's own
// fill width, taken as its longest line, and a break is unfilled when the first word of the
// next line would have fitted inside that width. That is the exact condition a greedy
// wrapper would not have produced, so a paragraph any human or tool wrapped in one pass
// passes, and only a paragraph edited in place fails.
//
// What it deliberately does not read, because each of these is legitimately short and
// reporting them is the noise that gets a check switched off:
//
//   - the last line of a paragraph, which nothing follows
//   - a line before a list item, a table row, a heading or an indented block, where the
//     break carries structure rather than width
//   - anything inside a fenced code block, where the author chose every break
//   - a line ending a sentence where the next begins a new one, since a writer may break
//     there on purpose
//
//   node scripts/check-doc-wrap.mjs

import { execFileSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");

/// How far under the block's fill width a break has to sit before it is worth reporting.
/// A word that fits by one or two characters is inside the noise of anybody's wrapping.
const SLACK = 12;

/// A break before one of these is structure rather than width.
const STRUCTURAL = /^(?:[-*+]\s|\d+[.)]\s|\||#|>|\s)/;

/// A doc line, as its indent, its marker, and the text after it.
const DOC = /^(\s*)(\/\/\/|\/\/!)(?: (.*))?$/;

const sources = () =>
  execFileSync("git", ["ls-files", "core/src", "bindings/node/src"], {
    cwd: root,
    encoding: "utf8",
  })
    .split("\n")
    .filter((rel) => rel.endsWith(".rs"));

/// Splits a file into runs of consecutive doc lines carrying text.
///
/// A blank `///` ends a run, because it ends a paragraph, and so does any line that is not a
/// doc comment. A fenced block inside a run is dropped rather than ending it, since the
/// prose either side of a fence is still one paragraph to a reader and neither half should
/// be measured against the fence's own line lengths.
const paragraphs = (body) => {
  const lines = body.split("\n");
  const runs = [];
  let run = [];
  let fenced = false;
  lines.forEach((line, index) => {
    const parsed = DOC.exec(line);
    const text = parsed?.[3];
    if (parsed && text !== undefined && /^\s*```/.test(text)) {
      fenced = !fenced;
      if (run.length > 0) runs.push(run);
      run = [];
      return;
    }
    if (!parsed || text === undefined || text.trim() === "" || fenced) {
      if (run.length > 0) runs.push(run);
      run = [];
      return;
    }
    run.push({ number: index + 1, width: line.length, text });
  });
  if (run.length > 0) runs.push(run);
  return runs;
};

const problems = [];

/// Reports the breaks in one paragraph that greedy wrapping would not have produced.
const readParagraph = (rel, run) => {
  if (run.length < 2) return;
  // The fill width is read off the lines that could have been wrapped. A line holding one
  // unbreakable token, which is what a long path or a URL is, sits wherever its own length
  // puts it and says nothing about the width the author was filling to. Counting one would
  // set the width above anything the prose reaches and report the whole paragraph.
  const wrappable = run.filter((line) => line.text.trim().includes(" "));
  if (wrappable.length === 0) return;
  const fill = Math.max(...wrappable.map((line) => line.width));
  for (let i = 0; i < run.length - 1; i += 1) {
    const here = run[i];
    const next = run[i + 1];
    if (STRUCTURAL.test(next.text)) continue;
    // A writer may end a line on a full stop and start the next sentence fresh.
    if (/[.!?]["')\]]?$/.test(here.text)) continue;
    const word = next.text.trimStart().split(/\s+/)[0] ?? "";
    if (word === "") continue;
    if (here.width + 1 + word.length + SLACK <= fill) {
      problems.push(
        `${rel}:${here.number} breaks at ${here.width} where the paragraph fills to ${fill}, and \`${word}\` would have fitted`,
      );
    }
  }
};

/// The check has to be able to fail, so it is run against a paragraph built to trip it and
/// one built not to, before it is run over the tree. An absence check whose reading matches
/// nothing passes for free, and this file exists because that shape was shipped twice.
const probe = () => {
  const filled = [
    "/// aaaaaaaaaa bbbbbbbbbb cccccccccc dddddddddd eeeeeeeeee ffffffffff gggg",
    "/// hhhhhhhhhh iiiiiiiiii",
  ].join("\n");
  const unfilled = [
    "/// aaaaaaaaaa bbbbbbbbbb cccccccccc dddddddddd eeeeeeeeee ffffffffff gggg",
    "/// hh",
    "/// iiiiiiiiii jjjjjjjjjj kkkkkkkkkk llllllllll mmmmmmmmmm nnnnnnnnnn oooo",
  ].join("\n");
  const count = (body) => {
    const before = problems.length;
    paragraphs(body).forEach((run) => readParagraph("probe", run));
    const found = problems.length - before;
    problems.length = before;
    return found;
  };
  if (count(filled) !== 0) {
    problems.push("the reading reports a paragraph that is already filled, so it is noise");
  }
  if (count(unfilled) === 0) {
    problems.push("the reading passes a paragraph with an unfilled break, so it proves nothing");
  }
};

probe();

const files = sources();
if (files.length === 0) {
  problems.push("no sources were listed, so the reading below ran over nothing");
}

let counted = 0;
for (const rel of files) {
  const runs = paragraphs(readFileSync(join(root, rel), "utf8"));
  counted += runs.length;
  runs.forEach((run) => readParagraph(rel, run));
}

if (problems.length > 0) {
  console.error("documentation paragraphs carry a break that wrapping would not have made:");
  for (const line of problems) {
    console.error(`  - ${line}`);
  }
  process.exit(1);
}

console.error(`${counted} documentation paragraph(s) are wrapped the way they were filled`);
