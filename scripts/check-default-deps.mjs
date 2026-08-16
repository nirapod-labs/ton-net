// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Nirapod Labs

// Holds the library's optional dependencies to being optional.
//
// Each one is pulled by a single feature and by nothing else, and that is a consequence
// of an `optional = true` line and the `dep:` spelling beside it in the feature list.
// Nothing reads either. Drop one, or name a feature in the `default` list that was not
// there, and the crate arrives in a build that was meant to be without it while every
// test still passes. Cargo catches only the opposite mistake: a `dep:` naming a
// dependency that stopped being optional does not resolve at all.
//
// What is asserted about each, and why it is that and not something wider:
//
//   lz4_flex is LZ4 compression of a serialized bag of cells, under `compress`.
//   NET-ADR-010 admits it on the condition that a default build compiles without it, and
//   `compress` is not a default feature, so that condition is readable as written: the
//   crate is absent from the default build.
//
//   getrandom draws the per-session ADNL randomness and tokio carries the socket and the
//   timer, both under `net`. `net` is a default feature, so neither is absent from a
//   default build and saying so would be false. The true statement is narrower and is the
//   one read here: with default features off, which is the build a browser target takes,
//   neither is in the tree. Their presence in the default build is asserted in the same
//   pass, because a dependency that vanished from the build the library ships by default
//   is a change nobody chose either.
//
// serde_json is deliberately not in that list, having been in it. The config reader
// parses JSON on the ungated path, so the dependency is unconditional and no feature
// gates it. It is read in the other direction, as a presence with the features off,
// because the way that fact changes is somebody putting the config reader behind a
// feature and leaving the ungated build without a reader.
//
// The absences are read against the same tree with the features on. An absence check
// whose reading never matches anything passes for free, so that pass is what makes the
// others mean something: the same reading has to find every crate when the features that
// pull them are enabled.
//
// The scope is one package's own feature sets over normal edges, and it is that narrow
// deliberately: the dev-dependencies carry tokio unconditionally, which is what
// `--edges normal` drops.
//
// Run with `node scripts/check-default-deps.mjs`. Exits non-zero naming the crate and
// which of the readings disagreed.

import { execFileSync } from "node:child_process";

const PACKAGE = "ton-net";

// Each optional dependency with the feature that is meant to be the only thing pulling
// it, and whether that feature is on by default, so a failure can say what was expected
// to gate it and in which build.
const OPTIONAL = [
  { crate: "lz4_flex", feature: "compress", byDefault: false },
  { crate: "getrandom", feature: "net", byDefault: true },
  { crate: "tokio", feature: "net", byDefault: true },
];

// A dependency no feature gates, read as a presence in the barest build there is.
const UNCONDITIONAL = ["serde_json"];

// A `cargo tree` line carries the crate name after the tree glyphs and before its
// version: `├── sha2 v0.10.9`. The root line has no glyphs. Requiring the ` v` and a
// digit after it keeps a name that is a prefix of another out of the match.
const named = (tree, crate) => new RegExp(String.raw`(^|\s)${crate} v\d`, "m").test(tree);

// Cargo's own refusal is one of the answers here: a manifest that keeps `dep:lz4_flex`
// in a feature while the dependency stops being optional does not resolve at all. That
// is a pass for the property and a failure for this run, so it is reported as cargo
// wrote it rather than as a stack trace.
const tree = (...args) => {
  try {
    return execFileSync("cargo", ["tree", "-p", PACKAGE, "--edges", "normal", ...args], {
      encoding: "utf8",
      stdio: ["ignore", "pipe", "pipe"],
    });
  } catch (failure) {
    console.error(`cargo tree could not resolve ${PACKAGE}:`);
    console.error(String(failure.stderr ?? failure.message).trimEnd());
    process.exit(1);
  }
};

const problems = [];

const bare = tree("--no-default-features");
const byDefault = tree();
const withFeatures = tree("--all-features");

for (const { crate, feature, byDefault: onByDefault } of OPTIONAL) {
  if (named(bare, crate)) {
    problems.push(
      `${crate} is in the ${PACKAGE} build with default features off; only the \`${feature}\` feature is meant to pull it`,
    );
  }
  if (onByDefault !== named(byDefault, crate)) {
    problems.push(
      onByDefault
        ? `${crate} is missing from the default build of ${PACKAGE}, which \`${feature}\` is a default feature of`
        : `${crate} is in the default build of ${PACKAGE}, which \`${feature}\` is not a default feature of`,
    );
  }
  if (!named(withFeatures, crate)) {
    problems.push(
      `${crate} is missing from the all-features build of ${PACKAGE}, so the readings above prove nothing`,
    );
  }
}

for (const crate of UNCONDITIONAL) {
  if (!named(bare, crate)) {
    problems.push(
      `${crate} is absent from the ${PACKAGE} build with default features off, so something now gates it`,
    );
  }
}

if (problems.length > 0) {
  console.error(problems.join("\n"));
  process.exit(1);
}

console.log(
  `${PACKAGE} with default features off carries none of ` +
    `${OPTIONAL.map(({ crate }) => crate).join(", ")}, and carries ${UNCONDITIONAL.join(", ")}`,
);
