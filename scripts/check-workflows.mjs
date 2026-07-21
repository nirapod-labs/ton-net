// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Nirapod Labs

// Holds the workflows to the three properties that are invisible until they matter.
//
// A third-party action runs with the workflow's token and can read anything the job
// can reach, so a moved tag is somebody else's code arriving in this build without a
// commit here. A commit hash is the only ref that cannot be moved. Dependabot moves
// the hashes on a schedule and writes the version it moved to in the trailing comment,
// which is what keeps a pin from becoming an old version nobody notices.
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
