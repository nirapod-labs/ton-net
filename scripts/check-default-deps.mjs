// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Nirapod Labs

// Holds the cell engine's optional dependencies to being optional.
//
// NET-ADR-010 lists "a default build compiles without it" among its verification items
// for lz4_flex, and NET-ADR-004 gives serde_json the same shape: each is an optional
// dependency and the feature named beside it is the only thing that pulls it. What is
// missing is narrower than it sounds. The default build is compiled and tested already,
// by the bare `cargo test` the gate runs before its all-features run, so the gap is not
// that the build goes unbuilt. The gap is that the two crates are absent from it as a
// consequence of two `optional = true` lines and nothing reads those lines. Drop either
// one, or name either feature in a `default` list, and the dependency arrives in every
// build with no test failing anywhere.
//
// The scope is one package's own default feature set over normal edges, and it is that
// narrow deliberately. The facade above the engine carries serde_json unconditionally to
// parse a network config, so the same sentence said about the workspace would be false,
// and the dev-dependencies carry it too, which is what `--edges normal` drops.
//
// The absence is read twice, once with the features off and once with them on. An
// absence check whose reading never matches anything passes for free, so the second pass
// is what makes the first one mean something: the same reading has to find both crates
// when the features that pull them are enabled.
//
// Run with `node scripts/check-default-deps.mjs`. Exits non-zero naming the crate and
// which of the two readings disagreed.

import { execFileSync } from "node:child_process";

const PACKAGE = "ton-net-cell";

// Each optional dependency with the feature that is meant to be the only thing pulling
// it, so a failure can say what was expected to gate it.
const OPTIONAL = [
  ["lz4_flex", "compress"],
  ["serde_json", "json"],
];

// A `cargo tree` line carries the crate name after the tree glyphs and before its
// version: `├── sha2 v0.10.9`. The root line has no glyphs. Requiring the ` v` and a
// digit after it keeps a name that is a prefix of another out of the match.
const named = (tree, crate) =>
  new RegExp(String.raw`(^|\s)${crate} v\d`, "m").test(tree);

// Cargo's own refusal is one of the answers here: a manifest that keeps `dep:lz4_flex`
// in a feature while the dependency stops being optional does not resolve at all. That
// is a pass for the property and a failure for this run, so it is reported as cargo
// wrote it rather than as a stack trace.
const tree = (...args) => {
  try {
    return execFileSync(
      "cargo",
      ["tree", "-p", PACKAGE, "--edges", "normal", ...args],
      { encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] },
    );
  } catch (failure) {
    console.error(`cargo tree could not resolve ${PACKAGE}:`);
    console.error(String(failure.stderr ?? failure.message).trimEnd());
    process.exit(1);
  }
};

const problems = [];

const byDefault = tree();
const withFeatures = tree("--all-features");

for (const [crate, feature] of OPTIONAL) {
  if (named(byDefault, crate)) {
    problems.push(
      `${crate} is in the default build of ${PACKAGE}; only the \`${feature}\` feature is meant to pull it`,
    );
  }
  if (!named(withFeatures, crate)) {
    problems.push(
      `${crate} is missing from the all-features build of ${PACKAGE}, so the reading above proves nothing`,
    );
  }
}

if (problems.length > 0) {
  console.error(problems.join("\n"));
  process.exit(1);
}

console.log(
  `${PACKAGE} default build is free of: ${OPTIONAL.map(([crate]) => crate).join(", ")}`,
);
