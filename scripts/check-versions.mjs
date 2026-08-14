// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Nirapod Labs

// Holds one version across two registries.
//
// The library ships as six crates on crates.io and eight packages on npm, built
// from one commit but published by two toolchains that know nothing about each
// other. Nothing mechanical keeps their version strings equal: release-plz moves
// the Cargo side, napi moves the npm side, and neither reads the other. Left
// alone they drift, and then two published artifacts claim to be the same library
// while carrying different numbers.
//
// The Cargo workspace version is the source of truth, read through `cargo
// metadata` rather than parsed out of a manifest, so this agrees with whatever
// cargo itself resolved.
//
//   node scripts/check-versions.mjs          report drift, exit 1 if any
//   node scripts/check-versions.mjs --fix    stamp the source of truth outward
//
// Registries spell a prerelease differently: crates.io takes `0.3.0-alpha.1`,
// npm takes the same string but needs `--tag alpha` to keep it off `latest`, and
// PyPI would want `0.3.0a1`. Only the npm side is here today. When a registry
// that respells the version arrives, this is where the mapping goes.

import { execFileSync } from "node:child_process";
import { existsSync, readFileSync, readdirSync, statSync, writeFileSync } from "node:fs";
import { dirname, join, relative } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
const root = join(here, "..");
const fix = process.argv.includes("--fix");

const drift = [];
const fixed = [];

/** Every version cargo reports for a workspace member. */
function cargoVersions() {
  const meta = JSON.parse(
    execFileSync("cargo", ["metadata", "--no-deps", "--format-version", "1"], {
      cwd: root,
      encoding: "utf8",
      maxBuffer: 32 * 1024 * 1024,
    }),
  );
  return meta.packages.map((pkg) => ({ name: pkg.name, version: pkg.version }));
}

const crates = cargoVersions();
if (crates.length === 0) {
  throw new Error("cargo metadata reported no workspace members");
}

// The crates move in lockstep; that is the decision the whole scheme rests on, so
// it is checked rather than assumed. A crate off on its own is not something this
// can fix, because there is no way to tell which of the two numbers was intended.
const versions = [...new Set(crates.map((c) => c.version))];
const version = crates.find((c) => c.name === "ton-net")?.version ?? versions[0];
if (versions.length > 1) {
  for (const crate of crates.filter((c) => c.version !== version)) {
    drift.push(`crate ${crate.name} is at ${crate.version}, ton-net at ${version}`);
  }
  console.error("the crates are not in lockstep, which no stamping can settle:");
  for (const line of drift) {
    console.error(`  - ${line}`);
  }
  process.exit(1);
}

/** Compares one field against the source of truth, or rewrites it under --fix. */
function reconcile(label, current, apply) {
  if (current === version) {
    return;
  }
  if (fix) {
    apply();
    fixed.push(`${label}: ${current} -> ${version}`);
  } else {
    drift.push(`${label} is at ${current}, the crates at ${version}`);
  }
}

const nodeManifests = [];
const binding = join(root, "bindings", "node", "package.json");
if (existsSync(binding)) {
  nodeManifests.push(binding);
}
const platforms = join(root, "bindings", "node", "npm");
if (existsSync(platforms)) {
  for (const entry of readdirSync(platforms)) {
    const dir = join(platforms, entry);
    if (statSync(dir).isDirectory() && existsSync(join(dir, "package.json"))) {
      nodeManifests.push(join(dir, "package.json"));
    }
  }
}

// A lockfile carries the version twice, at its root and on its own root package
// entry. It is not published, but npm refuses `npm ci` when it disagrees with the
// manifest, so a stale one turns into a failing install rather than a wrong one.
// This one had sat three versions behind before anything noticed.
const lockfile = join(root, "bindings", "node", "package-lock.json");
if (existsSync(lockfile)) {
  const label = relative(root, lockfile);
  const lock = JSON.parse(readFileSync(lockfile, "utf8"));
  let touched = false;
  reconcile(label, lock.version, () => {
    lock.version = version;
    touched = true;
  });
  if (lock.packages?.[""]) {
    reconcile(`${label} (root package)`, lock.packages[""].version, () => {
      lock.packages[""].version = version;
      touched = true;
    });
  }
  if (touched) {
    writeFileSync(lockfile, `${JSON.stringify(lock, null, 2)}\n`);
  }
}

for (const path of nodeManifests) {
  const label = relative(root, path);
  const manifest = JSON.parse(readFileSync(path, "utf8"));
  let touched = false;

  reconcile(label, manifest.version, () => {
    manifest.version = version;
    touched = true;
  });

  // The loader picks a binary through these, and npm resolves them exactly. One
  // left behind means the published package asks for a binary that does not exist
  // at that version, which fails at install rather than at publish.
  for (const [name, pinned] of Object.entries(manifest.optionalDependencies ?? {})) {
    reconcile(`${label} -> ${name}`, pinned, () => {
      manifest.optionalDependencies[name] = version;
      touched = true;
    });
  }

  if (touched) {
    writeFileSync(path, `${JSON.stringify(manifest, null, 2)}\n`);
  }
}

if (fixed.length > 0) {
  console.error(`stamped ${version} into ${fixed.length} place(s):`);
  for (const line of fixed) {
    console.error(`  - ${line}`);
  }
}

// The verification epoch is a second number with the same problem, and it is worse
// placed to be wrong. The transcript in `crates/ton-net/tests/epoch.rs` pins the number
// against what the verifier accepts, so behaviour and the constant cannot come apart.
// Nothing pins it against the prose, and the prose is where a consumer reads it: the
// crates.io front page states it, and it is the one number that decides whether a cached
// proven result needs checking again. It has already shipped stale once.
//
// So: read the constant, then refuse any living document that states a different literal
// beside the name. Documents that record a decision as it was made are left alone, since
// an ADR is a record rather than a description of today.
const epochSource = join(root, "crates/ton-net/src/lib.rs");
const epochMatch = readFileSync(epochSource, "utf8").match(
  /pub const VERIFY_EPOCH: u32 = (\d+);/,
);
if (!epochMatch) {
  console.error("no VERIFY_EPOCH declaration in crates/ton-net/src/lib.rs");
  process.exit(1);
}
const epoch = epochMatch[1];

// Every tracked document, rather than a list somebody has to remember to extend: a list
// goes stale the first time a document is added, and a document nobody added to it is
// exactly the one that would state the number and never be checked. Decision records are
// skipped because they record a value as it was when the decision was taken, which is
// history and not a description of this build.
const epochProse = execFileSync("git", ["ls-files", "*.md"], {
  cwd: root,
  encoding: "utf8",
})
  .split("\n")
  .filter((rel) => rel.length > 0 && !rel.startsWith("docs/adr/"));

const staleEpoch = [];
for (const rel of epochProse) {
  const path = join(root, rel);
  if (!existsSync(path)) {
    continue;
  }
  const lines = readFileSync(path, "utf8").split("\n");
  lines.forEach((line, index) => {
    if (!line.includes("VERIFY_EPOCH")) {
      return;
    }
    // A literal stated as the current value, in the shapes the corpus actually writes:
    // "1 today", "is 1", "= 1".
    const stated = line.match(/(?:\b(\d+) today\b|\bis (\d+)\b|=\s*(\d+)\b)/);
    const found = stated && (stated[1] ?? stated[2] ?? stated[3]);
    if (found && found !== epoch) {
      staleEpoch.push(`${rel}:${index + 1} says ${found}, the crate ships ${epoch}`);
    }
  });
}

if (drift.length > 0) {
  console.error(`the published artifacts disagree on the version (crates say ${version}):`);
  for (const line of drift) {
    console.error(`  - ${line}`);
  }
  console.error("run `node scripts/check-versions.mjs --fix` to stamp them");
  process.exit(1);
}

if (staleEpoch.length > 0) {
  console.error(`the verification epoch is stated stale (the crate ships ${epoch}):`);
  for (const line of staleEpoch) {
    console.error(`  - ${line}`);
  }
  console.error(
    "the constant is the source of truth; a document that states a number states this one",
  );
  process.exit(1);
}

console.error(
  `one version across ${crates.length} crate(s) and ${nodeManifests.length} npm package(s): ${version}, verification epoch ${epoch}`,
);
