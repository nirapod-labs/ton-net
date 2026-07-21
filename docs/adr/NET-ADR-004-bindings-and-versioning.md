---
id: NET-ADR-004
title: Binding order and a Rust-lockstep, per-artifact-published versioning scheme
status: proposed
date: 2026-07-20
supersedes: none
superseded-by: none
---

# NET-ADR-004: Binding order and a Rust-lockstep, per-artifact-published versioning scheme

## Context

The core reaches six ecosystems (Rust, Node, browser, Swift, Kotlin, Dart,
Python), each with its own binding toolchain, async model, and package registry.
Two decisions must be fixed up front because they shape the whole build and
release story: which binding to build in which order, and how versions are kept
coherent across a Rust core and six published packages.

The binding toolchains were surveyed with current versions: napi-rs (Node), best
async story with a real embedded tokio and prebuilt binaries; wasm-bindgen
(browser), single-threaded, no raw sockets; UniFFI (Swift and Kotlin from one
crate); flutter_rust_bridge (Dart, v2 beta); pyo3 with maturin (Python). The
hardest cross-cutting problem is async: five host async models (JS Promise, Swift
async/await, Kotlin suspend, Dart Future, Python asyncio) over one Rust async
core, plus the browser's no-threads, no-UDP constraint.

Three reference projects were studied for versioning and release. They diverge:
libsignal uses one unified version enforced across all bindings by a script;
automerge versions each artifact independently and decouples the user-facing npm
version from the Rust core; matrix-rust-sdk keeps the Rust crates in lockstep but
publishes each language's artifact from a separate repo with its own scheme (Swift
SemVer, Kotlin date tags, wasm npm on its own line).

## Decision

### Binding order

Build bindings in this order, each justified:

1. **Node (napi-rs)** first. Best async support, prebuilt-binary distribution, and
   fastest iteration; it validates the async-across-FFI design cheaply.
2. **Browser (wasm-bindgen)** second, not last. Its constraints (no threads, no
   raw UDP or TCP, `!Send` futures) are the most restrictive, and doing it early
   forces the sans-I/O core and the transport seam to be right before other
   bindings lock in an API that would need retrofitting. The browser build is
   liteserver-only through a WebSocket-to-liteserver proxy; DHT and UDP are
   unavailable there by protocol.
3. **Python (pyo3 + maturin)** third. Server, CLI, and test surface; keep the
   API mostly synchronous or asyncio-coroutine given pyo3's evolving native async.
4. **Swift + Kotlin (UniFFI)** fourth. One crate generates both mobile bindings;
   done after the API stabilizes because regenerating an XCFramework and an AAR
   across all architectures is the heaviest CI loop.
5. **Dart (flutter_rust_bridge)** last, optional. Capable but on a beta channel and
   every consuming app compiles the Rust; built only if Flutter is a real target.

### Async model

Standardize on: async at the Rust FFI boundary, an embedded tokio runtime on
native targets, and a single-threaded `spawn_local` executor with a WebSocket
transport on wasm, all over a transport-abstracted sans-I/O core. The concrete
pattern is matrix-rust-sdk's: a small export macro that injects the tokio runtime
on native and omits it on wasm, so one async surface maps to each host's idiom.

### Versioning

Adopt the matrix-rust-sdk model, which fits a multi-registry reality best:

- **The Rust crates move in lockstep**, one shared version. This is the version of
  the library. An earlier draft of this record named cargo-release as the tool;
  release-plz drives it instead, which is cargo-release plus the part that was
  going to be written by hand anyway: it reads the conventional commits, opens a
  release pull request carrying the version bump and the changelog for review, and
  publishes in dependency order on merge.
- **Each published language artifact carries its own package version** in its own
  registry (npm, PyPI, Swift Package Manager, Maven, pub.dev), because those
  ecosystems have their own conventions and cadences. The mapping from a library
  version to each artifact version is recorded, the way libsignal enforces and
  matrix documents.

  In practice that mapping is the identity, and deliberately so: the number is the
  same everywhere and only the channel differs, an npm dist-tag against a
  crates.io prerelease suffix. Keeping it that way means "which ton-net is this"
  has one answer. Where a registry will not accept the same string, PyPI spells a
  prerelease `0.3.0a1` rather than `0.3.0-alpha.1`, the mapping stops being the
  identity for that registry alone.

  No release tool spans this. release-plz moves the Cargo side and napi moves the
  npm side, and neither reads the other, so the stamping and the check that they
  agree are this project's own and run in CI.
- SemVer is measured against the **observable API and the wire behavior**. A wire
  format change or a proof-verification behavior change is breaking. Internal crate
  refactors are not. The library stays `0.x` until the API and the proof/sync
  guarantees are stable enough to promise, which for a wire-protocol library is a
  high bar (libsignal is still 0.x after years).

### Release channels

A milestone tag and a registry publish are separate acts, and this project keeps
them separate.

- **Every milestone is a git tag.** When a milestone's gate passes (see the
  roadmap), it is recorded as an annotated tag. The tag shows the work and pins a
  reproducible point; it does not by itself put a package on any registry.
- **Registry publishing is gated on the trust boundary, not on every tag.** A read
  is trust-minimized end to end only once block sync anchors it (v0.3.0). Before
  that point a published package would carry a version string that implies more
  assurance than the code delivers.
  - v0.1.0 and v0.2.0, if published at all, reach their registries only as
    pre-releases (`-alpha`), marked not for production, because reads are not yet
    verified against a synced anchor.
  - **v0.3.0 is the first ordinary registry release.** From v0.3.0 a read is
    verified against a validator-signature-anchored block with only the pinned
    init key-block trusted.
  - v1.0.0 freezes the API and the proof, sync, and TVM guarantees.
- **This composes with per-artifact versioning.** The pre-release channel maps onto
  each registry's own convention: a crates.io `0.1.0-alpha.N`, an npm dist-tag
  `alpha` on a `0.1.0-alpha.N` version, a PyPI `0.1.0aN`. The library version still
  moves in lockstep across the Rust crates; the channel is an orthogonal signal.

The type system already separates a `ServerReported` value from a verified one, so
a caller cannot confuse them in code. The registry channel is the second honest
signal, at the version-string level, that a build's verification promise is or is
not yet real.

## Alternatives considered

- **One unified version across everything (libsignal).** Rejected as the published
  scheme, kept as the Rust-side discipline. Forcing npm, PyPI, SPM and Maven to
  share one version fights each registry's conventions; the lockstep applies to
  the Rust crates, and each artifact gets its ecosystem-appropriate version.
- **Fully independent versions (automerge).** Rejected. Decoupling everything makes
  it hard to answer "which ton-net am I running." Rust lockstep gives one library
  version; per-artifact versions handle registry reality.
- **UniFFI for the browser too (matrix's experimental path).** Rejected. UniFFI's
  wasm output is behind an unstable single-threaded flag; use wasm-bindgen directly
  for the browser, which is the mature path.
- **Build mobile first (it is the reputation payoff).** Rejected. Mobile is the
  heaviest CI and should follow a stable API, not precede it. Node first, browser
  second to harden the constraints, mobile after the API settles.
- **Publish every milestone as an ordinary registry release.** Rejected. The
  library's whole value is that it verifies rather than trusts, and an ordinary
  release at v0.1.0 or v0.2.0 would ship a version whose reads are still server
  trusted. Every milestone is still tagged in git; the registry release waits for
  the trust boundary at v0.3.0.

## Consequences

- The async design is proven cheaply on Node before the expensive mobile bindings,
  and the browser's hard constraints shape the core early rather than forcing a
  late rewrite.
- Six release pipelines are real work; each is phased with its binding, not all at
  once. Per-platform artifact builds (prebuilt Node binaries, wasm bundle,
  XCFramework, AAR, wheels) are matrix CI jobs.
- One library version answers "which ton-net," while each registry sees a native
  version; the mapping is a maintained table.
- The `0.x` discipline sets expectations honestly: the API and the trust guarantees
  are not promised stable until they are, and v1.0.0 is the deliberate line where
  they are (see NET-ADR-002 and the roadmap).
- The first ordinary registry release is v0.3.0, where a read is trust-minimized
  end to end; v0.1.0 and v0.2.0 reach registries only as marked pre-releases, so a
  version string never implies verification the code has not yet earned.

## Chain scope

TON-specific (see NET-ADR-001).

## Custody and security

The library holds no user keys. Binding note: the FFI boundary must not widen the
key surface; the exposed API carries bytes and typed results, never a user key,
in every language.

## Verification

- The Node binding resolves an address and verifies an account proof end to end,
  exercising the full async path.
- The wasm binding opens a liteserver channel through a proxy and reads
  masterchain info, confirming the transport seam holds under the browser's
  constraints.
- A version-check step (the libsignal pattern) fails CI if the Rust crate versions
  drift out of lockstep.
