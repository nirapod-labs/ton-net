// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Nirapod Labs

// Holds the workflows to the four properties that are invisible until they matter.
//
// A third-party action runs with the workflow's token and can read anything the job
// can reach, so a moved tag is somebody else's code arriving in this build without a
// commit here. A commit hash is the only ref that cannot be moved. Dependabot moves
// the hashes on a schedule and writes the version it moved to in the trailing comment,
// which is what keeps a pin from becoming an old version nobody notices.
//
// An image a shell step runs is the same code arriving the same way, and nothing moves
// it on a schedule: Dependabot reads a Dockerfile and a `container:` key, not an image
// named inside a script, so a digest written there is moved by hand and stays where it
// was put. That is why such a pin looks frozen, and why the version it stands for is
// written beside it. The digest does for an image what the commit hash does for an
// action, so it is what is required. A step that means to follow a moving tag says so
// in its own comment, naming the image after `unpinned image` and giving the reason,
// and this reads that rather than failing on it.
//
// The other two are cheaper to state than to debug: a workflow with no `permissions`
// block takes whatever the repository setting hands it, and a scheduled job with no
// `if` on the repository runs in every fork that turns Actions on.
//
// Run with `node scripts/check-workflows.mjs`. Exits non-zero on the first workflow
// that breaks one of them.

import { readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";

const DIR = ".github/workflows";
const REPOSITORY = "nirapod-labs/ton-net";

// A local action, a docker action, or a step in this repository is not a third-party
// ref and has nothing to pin.
const LOCAL = /^(\.\/|docker:\/\/)/;
const PINNED = /^[^@]+@[0-9a-f]{40}$/;

// An image the way a shell line carries it: `name:tag` or `name@sha256:...`, either
// one optionally behind a registry and a namespace. Docker holds the name to lowercase
// and the tag to no slash, which is what keeps a `--volume "$PWD:/build"` and a workdir
// of `/build/bindings/node` out of the match. A bare `name` is `:latest` and reads here
// as the ordinary word it looks like, so it is the one shape this does not see.
const IMAGE = /(?<![\w$./:@-])[a-z0-9][a-z0-9._/-]*(?::[\w][\w.-]*|@sha256:[0-9a-f]+)(?![\w.:/-])/g;
const DIGEST = /@sha256:[0-9a-f]{64}$/;

// Only a step that starts a container is read for images. Every other step is shell
// this has no business parsing, and `foo:bar` is a common enough thing to echo.
const CONTAINER = /\b(docker|podman)\b/;

// The image is often named once and read from several legs, so `$NAME` in the step and
// the assignment it resolves to are two halves of one reference.
const VARIABLE = /\$\{?([A-Z][A-Z0-9_]*)\}?/g;

// The deliberate exception, written where the reason for it belongs.
const EXCEPTION = /unpinned image\b/;

// The jobs of one workflow as `[name, body]`, read off the indentation rather than
// through a YAML parser: two spaces under `jobs:` starts a job, and the next one ends
// it. Keeping this dependency-free is what lets the check run in the hermetic gate.
function jobsOf(lines) {
  const start = lines.findIndex((line) => line === "jobs:");
  if (start < 0) return [];

  const jobs = [];
  let current = null;
  for (const line of lines.slice(start + 1)) {
    const header = line.match(/^ {2}([\w-]+):\s*$/);
    if (header) {
      current = [header[1], ""];
      jobs.push(current);
    } else if (current && (line === "" || line.startsWith("  "))) {
      current[1] += `${line}\n`;
    } else if (line !== "" && !line.startsWith(" ")) {
      break; // back to the top level, so `jobs:` is over
    }
  }
  return jobs;
}

// The `run:` blocks of one workflow, each as the `[index, line]` pairs of its shell
// body. Read off the indentation like the jobs above: a block scalar runs to the first
// line that is no further right than the `run:` key itself.
function runBlocksOf(lines) {
  const blocks = [];
  lines.forEach((line, index) => {
    if (!/^\s*(-\s+)?run:/.test(line)) return;

    const column = line.indexOf("run:");
    const block = [[index, line]];
    for (let i = index + 1; i < lines.length; i += 1) {
      const next = lines[i];
      if (next.trim() !== "" && next.search(/\S/) <= column) break;
      block.push([i, next]);
    }
    blocks.push(block);
  });
  return blocks;
}

// The variables a workflow assigns, by name. An image two legs share is named once in
// `env:` and read as `$NAME` from both, which makes the assignment the line its digest
// has to be right on.
function variablesOf(lines) {
  const variables = new Map();
  lines.forEach((line, index) => {
    const assignment = line.match(/^\s+([A-Z][A-Z0-9_]*):\s+(\S+)/);
    if (assignment) {
      variables.set(assignment[1], { index, value: assignment[2] });
    }
  });
  return variables;
}

// The lines an exception can be written on, walking up from the image: the step that
// names it, and the comment block directly above that step. The reason a tag is
// allowed to move belongs beside the step, where it is read with the thing it excuses.
function stepText(lines, index) {
  const text = [];
  let i = index;
  for (; i >= 0; i -= 1) {
    text.push(lines[i]);
    if (/^\s*(-\s|#|$)/.test(lines[i])) break;
  }
  for (i -= 1; i >= 0 && /^\s*#/.test(lines[i]); i -= 1) {
    text.push(lines[i]);
  }
  return text.join("\n");
}

// Whether a step excuses this image from the pin. The exception has to name the image
// and then say something about it, which is what holds it to the one it was written
// for: a second image added to the step later is a second decision, not a covered one.
function excused(lines, index, ref) {
  return stepText(lines, index)
    .split("\n")
    .some((line) => {
      const named = line.indexOf(ref);
      if (named < 0 || !EXCEPTION.test(line)) return false;
      return /\S/.test(line.slice(named + ref.length));
    });
}

// Every image a shell step of this workflow starts, checked at the line that names it.
function imageProblems(path, lines) {
  const found = [];
  const variables = variablesOf(lines);

  // `assigned` is set where the reference is a YAML value, which has room for a
  // trailing comment. One mid-command sits on a line ending in `\`, which has not.
  const check = (index, ref, assigned) => {
    const line = lines[index];
    if (excused(lines, index, ref)) return;
    if (!DIGEST.test(ref)) {
      found.push(`${path}:${index + 1}: ${ref} is not pinned to a digest`);
    } else if (assigned && !/#\s*\S/.test(line.slice(line.indexOf(ref) + ref.length))) {
      found.push(
        `${path}:${index + 1}: ${ref} has no trailing comment saying which version it is`,
      );
    }
  };

  for (const block of runBlocksOf(lines)) {
    const text = block.map(([, line]) => line).join("\n");
    if (!CONTAINER.test(text)) continue;

    // An image written into the step itself.
    for (const [index, line] of block) {
      for (const [ref] of line.matchAll(IMAGE)) {
        check(index, ref, false);
      }
    }

    // An image the step reads out of a variable, checked at the assignment, which is
    // the line a digest can be moved on.
    const read = [...text.matchAll(VARIABLE)].map(([, name]) => name);
    for (const name of new Set(read)) {
      const assignment = variables.get(name);
      if (!assignment) continue;
      for (const [ref] of assignment.value.matchAll(IMAGE)) {
        check(assignment.index, ref, true);
      }
    }
  }

  // One image two steps share is one image, not two problems.
  return [...new Set(found)];
}

const problems = [];

for (const name of readdirSync(DIR).filter((f) => f.endsWith(".yml") || f.endsWith(".yaml"))) {
  const path = join(DIR, name);
  const text = readFileSync(path, "utf8");
  const lines = text.split("\n");

  lines.forEach((line, index) => {
    const uses = line.match(/^\s*-?\s*uses:\s*(\S+)/);
    if (!uses || LOCAL.test(uses[1])) return;
    if (!PINNED.test(uses[1])) {
      problems.push(`${path}:${index + 1}: ${uses[1]} is not pinned to a commit hash`);
    } else if (!/#\s*\S/.test(line.slice(uses.index + uses[0].length))) {
      problems.push(
        `${path}:${index + 1}: ${uses[1]} has no trailing comment saying which version it is`,
      );
    }
  });

  problems.push(...imageProblems(path, lines));

  // A `permissions` block at the top of the file, not only inside one job: a job that
  // does not state its own inherits the file's, and the file's is the floor.
  if (!/^permissions:$/m.test(text)) {
    problems.push(`${path}: no top-level permissions block`);
  }

  // Only a workflow a schedule can start needs the guard, and only on the jobs the
  // schedule would reach. A job that runs on push or pull request is welcome in a fork.
  if (/^ {2}schedule:$/m.test(text)) {
    for (const [job, body] of jobsOf(lines)) {
      // A job waiting on a guarded one is already guarded: a skipped dependency skips it.
      if (body.includes(REPOSITORY) || /^\s+needs:/m.test(body)) continue;
      problems.push(
        `${path}: job \`${job}\` does not name the repository, so a fork's schedule runs it`,
      );
    }
  }
}

if (problems.length > 0) {
  console.error(problems.join("\n"));
  process.exit(1);
}

console.log(`workflows pinned, scoped and guarded: ${readdirSync(DIR).length} file(s)`);
