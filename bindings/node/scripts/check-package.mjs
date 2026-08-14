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

// Only stdout is captured. `npm pack` runs the prepack script, whose own output would
// otherwise land in the same stream as the JSON, and inheriting stderr keeps npm's
// notices where a reader can still see them.
const raw = execFileSync("npm", ["pack", "--dry-run", "--json"], {
  cwd: binding,
  encoding: "utf8",
  stdio: ["ignore", "pipe", "inherit"],
});

// The shape is read rather than assumed. npm has reported this as a one-element array,
// and a release failed here on a newer npm that answered with something else, with a
// TypeError naming a property instead of the output that produced it. Whatever arrives,
// this either finds the file list or says what it got.
let parsed;
try {
  parsed = JSON.parse(raw);
} catch (error) {
  console.error(`npm pack --json did not return JSON: ${error.message}`);
  console.error(raw.slice(0, 400));
  process.exit(1);
}
const entry = Array.isArray(parsed) ? parsed[0] : parsed;
if (!entry || !Array.isArray(entry.files)) {
  console.error("npm pack --json returned no file list for the main package");
  console.error(JSON.stringify(parsed).slice(0, 400));
  process.exit(1);
}
const shipped = entry.files.map((file) => file.path);

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

    // The readme napi generates says the binary belongs to the package name
    // prefix, which is not a package anyone can install: it is a string that
    // exists only to name these. Someone who lands here while debugging an
    // install would go looking for it and find nothing.
    const readme = join(dir, "README.md");
    if (!existsSync(readme)) {
      problems.push(`${manifest.name} has no README.md; run \`npm run prepack\``);
    } else {
      const text = readFileSync(readme, "utf8");
      if (!text.includes(`npmjs.com/package/${main.name}`)) {
        problems.push(`${manifest.name} does not point a reader at ${main.name}`);
      }
      if (new RegExp(`\`${main.napi.packageName}\``).test(text)) {
        problems.push(
          `${manifest.name} names ${main.napi.packageName} as if it were installable`,
        );
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
