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
// exactly the one that would state the number and never be checked.
//
// A record is the exception, because it states a value as of when it was written and stays
// correct at every later value. A decision record is one, and so are a release plan and the
// changelog: appending "the current version is 0.4.0" to `docs/plan/v0.4.0.md` failed the
// gate on a document that was right.
const record = (rel) =>
  rel.startsWith("docs/adr/") || rel.startsWith("docs/plan/") || rel === "CHANGELOG.md";

const living = execFileSync("git", ["ls-files", "*.md"], {
  cwd: root,
  encoding: "utf8",
})
  .split("\n")
  .filter((rel) => rel.length > 0 && !record(rel));

// `docs/versions.md` and `docs/api-design.md`, the two documents a consumer reads for this
// value, both write the literal as `1` rather than 1. Matching the raw line read the
// backtick as part of the number, so the check passed corpus-wide while both stated an
// epoch the crate had left behind.
const unstyled = (line) => line.replace(/`/g, "");

const staleEpoch = [];
for (const rel of living) {
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
    // "1 today", "is 1", "currently 1", "= 1".
    const stated = unstyled(line).match(
      /(?:\b(\d+) today\b|\bis (\d+)\b|\bcurrently (\d+)\b|=\s*(\d+)\b)/,
    );
    const found = stated && (stated[1] ?? stated[2] ?? stated[3] ?? stated[4]);
    if (found && found !== epoch) {
      staleEpoch.push(`${rel}:${index + 1} says ${found}, the crate ships ${epoch}`);
    }
  });
}

// The version had it worse: the reconciliation above covers the manifests, which no human
// writes, and nothing covered the prose, which is the only place a reader meets the number.
// Four documents stated 0.3.0 across three releases.
//
// A bare version literal cannot be the trigger, because most of them are correct history.
// "v0.3.0 is the first published version" stays true at every later version, and a check
// that failed on it would be turned off within a release.
//
// Sharing a line with today or current is not enough either, and the corpus says why: the
// release sequence opens on where the project "stands today to v1.0.0", a target rather
// than a state, and names the two unpublished tags one clause after stating the current
// version. A line carries a currency claim and correct history at once. So the version has
// to be what the claim is about, which in every shape the corpus writes means it follows an is:
// "the version today is X", "today it is X", "the current crate version is X". A number
// reached by to, and, or are is left alone.
//
// A currency claim phrased some third way is invisible here.
const staleVersion = [];
for (const rel of living) {
  const path = join(root, rel);
  if (!existsSync(path)) {
    continue;
  }
  const lines = readFileSync(path, "utf8").split("\n");
  lines.forEach((line, index) => {
    const plain = unstyled(line);
    if (!/\b(?:today|current)\b/i.test(plain)) {
      return;
    }
    for (const [, stated] of plain.matchAll(/\bis\s+v?(\d+\.\d+\.\d+)\b/g)) {
      if (stated !== version) {
        staleVersion.push(`${rel}:${index + 1} says ${stated}, the crates are at ${version}`);
      }
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

if (staleVersion.length > 0) {
  console.error(`a document states a stale version as the current one (the crates are at ${version}):`);
  for (const line of staleVersion) {
    console.error(`  - ${line}`);
  }
  console.error("a line that says today or current carries the version the crates carry");
  process.exit(1);
}

console.error(
  `one version across ${crates.length} crate(s) and ${nodeManifests.length} npm package(s): ${version}, verification epoch ${epoch}`,
);
