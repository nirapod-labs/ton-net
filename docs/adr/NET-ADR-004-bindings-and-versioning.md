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

- **The Rust crates move in lockstep**, one shared version, enforced by
  cargo-release `shared-version = true`. This is the version of the library.
- **Each published language artifact carries its own package version** in its own
  registry (npm, PyPI, Swift Package Manager, Maven, pub.dev), because those
  ecosystems have their own conventions and cadences. The mapping from a library
  version to each artifact version is recorded, the way libsignal enforces and
  matrix documents.
- SemVer is measured against the **observable API and the wire behavior**. A wire
  format change or a proof-verification behavior change is breaking. Internal crate
  refactors are not. The library stays `0.x` until the API and the proof/sync
  guarantees are stable enough to promise, which for a wire-protocol library is a
  high bar (libsignal is still 0.x after years).

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

## Chain scope

TON-specific (see NET-ADR-001).

## Custody and security

Custody gate: pass (no keys). Binding note: the FFI boundary must not widen the
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
