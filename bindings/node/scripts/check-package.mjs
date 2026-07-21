// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Nirapod Labs

// Asserts what the published tarballs must contain, before a release rather than
// after one. An npm package cannot be replaced once published, only deprecated, so
// a tarball missing its license or its type definitions is permanent.
//
// Three things are checked:
//   - the main package carries the license, the notice, and the type definitions
//   - it does not carry the Rust sources, the test, or a compiled binary
//   - every per-platform package carries the license and the notice too, since
//     each is a separate redistribution under Apache-2.0 section 4

import { execFileSync } from "node:child_process";
import { existsSync, readdirSync, readFileSync, statSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
const binding = join(here, "..");

const REQUIRED = ["LICENSE", "NOTICE", "README.md", "index.js", "index.d.ts", "package.json"];
const FORBIDDEN = [/^src\//, /^scripts\//, /\.node$/, /^test\.mjs$/, /^npm\//, /^Cargo\./];

const problems = [];

const packed = JSON.parse(
  execFileSync("npm", ["pack", "--dry-run", "--json"], { cwd: binding, encoding: "utf8" }),
);
const shipped = packed[0].files.map((entry) => entry.path);

for (const name of REQUIRED) {
  if (!shipped.includes(name)) {
    problems.push(`the main package does not ship ${name}`);
  }
}
for (const path of shipped) {
  const matched = FORBIDDEN.find((pattern) => pattern.test(path));
  if (matched) {
    problems.push(`the main package ships ${path}, which ${matched} excludes`);
  }
}

const platforms = join(binding, "npm");
if (!existsSync(platforms)) {
  problems.push("no per-platform packages exist; run `napi create-npm-dirs`");
} else {
  const main = JSON.parse(readFileSync(join(binding, "package.json"), "utf8"));
  const optional = Object.keys(main.optionalDependencies ?? {});

  for (const entry of readdirSync(platforms)) {
    const dir = join(platforms, entry);
    if (!statSync(dir).isDirectory()) {
      continue;
    }
    const manifest = JSON.parse(readFileSync(join(dir, "package.json"), "utf8"));

    // The loader resolves the binary through an optional dependency. A platform
    // package that nothing depends on is published and then never installed.
    if (!optional.includes(manifest.name)) {
      problems.push(`${manifest.name} is not an optionalDependency of the main package`);
    }
    if (manifest.version !== main.version) {
      problems.push(`${manifest.name} is at ${manifest.version}, the main package at ${main.version}`);
    }
    for (const name of ["LICENSE", "NOTICE"]) {
      if (!existsSync(join(dir, name))) {
        problems.push(`${manifest.name} has no ${name}; run \`npm run prepack\``);
      }
    }
  }

  for (const name of optional) {
    const suffix = name.slice(`${main.napi.packageName}-`.length);
    if (!existsSync(join(platforms, suffix))) {
      problems.push(`${name} is depended on but has no directory under npm/`);
    }
  }
}

if (problems.length > 0) {
  console.error("the packages are not ready to publish:");
  for (const problem of problems) {
    console.error(`  - ${problem}`);
  }
  process.exit(1);
}

console.error(`packages check out: main plus ${readdirSync(platforms).length} platforms`);
