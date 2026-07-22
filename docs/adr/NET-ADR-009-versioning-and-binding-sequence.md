---
id: NET-ADR-009
title: One binding to v1.0.0, and versioning across six axes rather than one
status: accepted
date: 2026-07-22
supersedes: NET-ADR-004
superseded-by: none
---

# NET-ADR-009: One binding to v1.0.0, and versioning across six axes rather than one

## Context

NET-ADR-004 fixed two things: a binding order that placed Node, browser, Python,
Swift and Kotlin inside v1.0.0, and a versioning scheme of one lockstep library
version mapped to each registry as the identity where the registry allows it.

NET-ADR-008 changed the scope under both. What v1.0.0 now covers is several times
what exists, and five binding surfaces multiply every core addition by five. A core
that size is not one a single maintainer can carry to completeness while chasing
five of them.

The versioning half needs replacing for a different reason. What NET-ADR-004
describes is a single SemVer number and a registry mapping, which is the right
answer to the question it asked. But a verifying, multi-network, multi-language
protocol library carries state that moves on schedules the library does not
control: upstream schema files, TON's own TVM global version, the network config
and its pinned init block. Versioning by feature, where v0.4.0 means the DHT
landed, describes a roadmap rather than a compatibility contract. A consumer
cannot read a feature-shaped version number and learn whether an upgrade changes
what the library will accept as proven.

## Decision

### Binding sequence

Take the Rust core to parity first. Carry the **Node binding alongside it** and no
other. v1.0.0 is the core at parity plus Node.

Node stays the single early binding because it earns its cost: building it has
already exposed two API holes that the core's own tests did not, an
unconstructible `BlockIdExt` and a missing `verify_account` on the facade. One
consumer of the API is worth its weight. Five are not, before the API settles.

The browser, Python, Swift and Kotlin bindings ship after v1.0.0. Bindings are
additive and do not change the core, so deferring them costs calendar and nothing
else. NET-ADR-004's async model is unchanged and carried forward: async at the
Rust FFI boundary, an embedded tokio runtime on native targets, and a
single-threaded executor with a WebSocket transport on wasm, over a sans-I/O core.

### Versioning across six axes

The governing rule is that **a number is for something a consumer compares, and a
manifest is for something a consumer queries**. Six axes follow from it.

**Axis 1, the library version.** One SemVer number across every language, mapped
per registry. What needs recording is not the number but what counts as breaking,
because the ordinary reading of SemVer misses two of the three classes that matter
here:

| Class | Example | Bump |
|---|---|---|
| API break | a signature, type or removal | major |
| Behavioural break | something that verified now fails, or something refused now passes | major |
| Wire break | a different protocol revision | major |

Pre-1.0, Cargo already treats `0.Y` as the major, so `0.4` to `0.5` is breaking
there. npm and PyPI do not share that rule, so the policy is stated rather than
inherited: **`0.MINOR` is breaking and `0.MINOR.PATCH` is compatible, in every
ecosystem.**

**Axis 2, the verification epoch.** A monotonic integer, `VERIFY_EPOCH`, exposed at
runtime and incremented whenever the accept and reject boundary of the proof
engine moves. It is independent of the library version, because an API can stay
byte-identical while what the library believes changes underneath it.

It increments when a new proof kind is accepted, when an acceptance condition
tightens or loosens, when the signature-weight rule changes, or when a freshness
default changes. Each increment carries a changelog entry stating the delta in
accept and reject terms.

Two things earn it its place. A consumer that recorded "verified under epoch 3"
can decide whether an upgrade obliges re-verification. And it puts a question in
front of the maintainer at every release that is otherwise easy not to ask. A
verifier that cannot say when its own judgement last changed is asking to be
trusted rather than checked, which is the thing this library exists not to do.

**Axis 3, the protocol support manifest.** The pinned upstream inputs move on
someone else's schedule, so they are a capability statement rather than a version.
It is queryable at runtime and diffed in CI:

```
ton_net::support() -> Support {
    lite_api:    SchemaRev { sha256, upstream_commit },
    ton_api:     SchemaRev { .. },
    block_tlb:   SchemaRev { .. },
    tvm_global_version: 4..=11,
    config_params:      [0, 1, 4, 8, 12, 15, 16, 17, 18, 20, 21, 28, 34, ..],
    capabilities: [Liteserver, Proofs, BlockSync, Dht, Rldp, Overlay, Tvm, Wallet],
}
```

This generalises the drift check that already runs as `check-config-drift.mjs`: CI
compares the manifest against upstream and fails when a schema moves underneath
the library.

**Axis 4, the TVM global-version matrix.** TON gates opcodes on `global_version`
from config parameter 8, so a TVM runs older semantics for older blocks and
current semantics for current ones. That is a compatibility table of the same
shape as an Ethereum client's fork schedule, and it belongs in a table rather than
in a package version. Each opcode declares its minimum global version, and an
inventory test asserts the table is complete.

**Axis 5, the registry mapping.** One library version, several registries with
incompatible grammars. PEP 440 is the forcing function, because it cannot spell
`-alpha.1`. The mapping is generated by `check-versions.mjs` and never edited by
hand:

| Library | crates.io | npm | PyPI | Maven | SwiftPM |
|---|---|---|---|---|---|
| 0.4.0 | 0.4.0 | 0.4.0 | 0.4.0 | 0.4.0 | v0.4.0 |
| 0.4.0-alpha.1 | 0.4.0-alpha.1 | 0.4.0-alpha.1 | 0.4.0a1 | 0.4.0-alpha-1 | tag only |
| 1.0.0-rc.2 | 1.0.0-rc.2 | 1.0.0-rc.2 | 1.0.0rc2 | 1.0.0-rc-2 | tag only |

**Axis 6, toolchain floors and feature flags.** A minimum supported Rust version
rises on a minor bump and never on a patch. Each binding carries its own floor;
the split is already real, with the core at 1.85 and the Node binding at 1.88
because napi-rs requires it.

At the scope NET-ADR-008 sets, feature flags stop being optional. A wallet must
not compile a TVM it never calls. That makes feature composition part of the
compatibility surface:

```
default  = ["liteserver", "proofs", "sync"]
optional = ["tvm", "dht", "rldp", "overlay", "wallet", "toncenter"]

adding a feature          -> minor
removing or renaming one  -> major
changing the default set  -> major, because it changes what a consumer gets
```

Every combination has to build, so `--all-features` and `--no-default-features`
both belong in CI. The bindings complicate it, because napi cannot conditionally
export cleanly, and whether the Node package ships one full artifact or several is
a decision the binding milestone owns.

### Support policy

Stated as it is rather than as it would sound better. Pre-1.0, security fixes land
on the latest minor only. From v1.0.0, on the latest minor and the one before it
for six months. A deprecation carries one minor's warning before removal.

### Release channels

Carried forward from NET-ADR-004 unchanged, because the reasoning holds. A
milestone tag and a registry publish are separate acts. Every milestone is an
annotated git tag. v0.1.0 and v0.2.0 reach a registry only as marked pre-releases,
v0.3.0 is the first ordinary registry release because a read is trust-minimized
end to end from there, and v1.0.0 freezes the API.

## Alternatives considered

- **Keep five bindings inside v1.0.0.** Rejected. At 101,000 lines of new core it
  does not converge, and the comparison shows the shape: no bindings is how the
  reference implementation reached this size.
- **No binding until the core is done.** Rejected. The Node binding has already
  found two API holes the core's own tests missed. One consumer is the cheapest
  design review available.
- **One version number and nothing else, as NET-ADR-004 had it.** Rejected. It
  cannot express that an upgrade changed what the library accepts as proven, which
  for a verifier is the fact a consumer most needs.
- **Version the proof engine as its own SemVer crate.** Rejected. It answers the
  same question as the verification epoch and asks consumers to track two version
  numbers to do it. An integer they can compare is enough.
- **Fold the schema revisions into the library version.** Rejected. Upstream moves
  on its own schedule and often without affecting behaviour. Bumping a public
  version for an upstream comment change trains consumers to ignore bumps.

## Consequences

- v1.0.0 arrives with one binding. The mobile reach that NET-ADR-004 treated as
  part of the 1.0 promise becomes a post-1.0 line.
- `VERIFY_EPOCH` must be decided at every release that touches the proof engine,
  which is deliberate friction on the one path where silence is dangerous.
- The support manifest is a new public surface and is therefore itself covered by
  Axis 1: changing its shape is an API break.
- Feature flags multiply the CI matrix. Every published combination is built, and
  the count grows with each optional capability.
- The registry mapping stops being the identity for PyPI and Maven at the first
  pre-release, which is exactly where NET-ADR-004 predicted it would.

## Chain scope

TON-specific for the TVM global-version axis and the schema revisions. The
versioning discipline itself is chain-agnostic.

## Custody and security

The FFI boundary carries bytes and typed results, never a user key, in every
language. The verification epoch is a security-relevant signal and is treated as
one: an increment is never silent, and a release that changes what is accepted
without recording it is a release defect.

## Verification

- A CI step fails if the Rust crate versions drift out of lockstep, and a second
  fails if any registry version disagrees with the generated mapping.
- A test asserts that `VERIFY_EPOCH` changed whenever the proof-engine acceptance
  fixtures changed, so the two cannot drift apart unnoticed.
- The support manifest is compared against the pinned upstream schema files in CI.
- `--all-features` and `--no-default-features` both build and test.
