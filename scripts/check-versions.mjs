// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Nirapod Labs

// Holds one version across two registries.
//
// The library ships as six crates on crates.io and nine packages on npm, built
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

if (drift.length > 0) {
  console.error(`the published artifacts disagree on the version (crates say ${version}):`);
  for (const line of drift) {
    console.error(`  - ${line}`);
  }
  console.error("run `node scripts/check-versions.mjs --fix` to stamp them");
  process.exit(1);
}

console.error(
  `one version across ${crates.length} crate(s) and ${nodeManifests.length} npm package(s): ${version}`,
);
