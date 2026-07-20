---
id: NET-ADR-005
title: Include a TVM for local get-method execution, adapting an existing Rust TVM if one fits
status: proposed
date: 2026-07-20
supersedes: none
superseded-by: none
---

# NET-ADR-005: Include a TVM for local get-method execution, adapting an existing Rust TVM if one fits

## Context

A `liteServer.runSmcMethod` response returns a computed value, but its proofs
cover only the account's code, data, and the config (c7), not the computation. So
a client that reports the server's returned value trusts the server for the
result. The pytoniq reference states this outright ("remote get method result is
not provable") and provides local execution instead: fetch the proven code, data
and config, then run the get-method in a local TVM.

A complete, proof-verifying client (NET-ADR-002) cannot leave this hole. Reading a
balance is proven; calling `get_wallet_data`, resolving a TON DNS name, or reading
a jetton balance goes through a get-method and, without a local TVM, is
server-trusted. Closing the hole needs a TVM.

A TVM is a large component: a stack machine with 200-plus opcodes, cell and
continuation semantics, gas accounting, and exact-match behavior against the
reference, because a get-method that computes differently from the network is
worse than no answer. Whether to write one, adapt one, or embed one is a real
decision with real cost, which is why it gets its own ADR rather than being
assumed inside the scope.

The landscape shows candidate Rust TVMs exist but need validation: the Everscale
and TON-fork ecosystems have TVM implementations (for example ton-vm / tvm crates
in the everx and broxus lineages), and pytoniq uses a `pytvm` binding. None was
confirmed byte-exact against TON mainnet TVM semantics in this research, and the
Everscale VM has diverged from TON's over time.

## Decision

Include a TVM in the v1.0.0 scope, so local get-method execution against proven
state is available and a computed result can be trustless.

Prefer to **adapt or wrap an existing permissively-licensed Rust TVM** over
writing one from scratch, contingent on a validation gate: the candidate must
reproduce TON mainnet get-method results exactly across a conformance corpus of
real accounts (wallets, jettons, DNS, common contracts). If no candidate passes
the gate, fall back to porting the reference C++ TVM semantics, which is the
larger effort and must be scheduled as such.

The TVM sits above the proof engine and is fed only proven inputs: proven account
code and data, and proven config for c7. The API surfaces a locally-executed
get-method result as a distinct, trust-minimized result type, separate from a raw
`runSmcMethod` server response, so a consumer can never mistake one for the other.

## Alternatives considered

- **Defer the TVM past v1.0.0.** Rejected under the completeness bar (NET-ADR-002).
  It would ship a "complete client" with a server-trusted hole on the most common
  read pattern (get-methods). A complete client closes it.
- **Write a TVM from scratch for v1.0.0.** Rejected as the default path, kept as
  the fallback. A from-scratch TVM is the single largest piece of the project and
  would dominate the schedule; adapting a validated existing one is far cheaper if
  a candidate passes the gate. The gate exists precisely so "adapt" does not become
  "adapt something subtly wrong."
- **Bind pytoniq's `pytvm` or the C++ TVM over FFI.** Rejected for the same reasons
  as binding tonlib generally (NET-ADR-001): it breaks the single-Rust-core model,
  will not compile to wasm, and drags a foreign build into every consumer.
- **Trust the server for get-methods and document it.** Rejected. Honest, but it
  concedes the completeness and trust-minimization the project is built to claim.

## Consequences

- v1.0.0 can execute get-methods locally against proven state, closing the last
  trust hole on the read path.
- The validation gate is a hard schedule risk: if no existing Rust TVM passes,
  the fallback (port the C++ semantics) is a major effort and v1.0.0 moves out
  accordingly. The roadmap treats the TVM as the highest-uncertainty item and
  sequences it so the rest of the client ships without waiting on it.
- The TVM is wasm-relevant too (a browser consumer wants trustless get-methods),
  so the chosen or ported VM must be pure-Rust and wasm-compatible, which further
  narrows candidates.
- Because the TVM consumes only proven inputs, its trust story is clean: garbage
  in is impossible by construction, and the only question is execution fidelity,
  which the conformance corpus measures.

## Chain scope

TON-specific (see NET-ADR-001). The TVM is TON's virtual machine.

## Custody and security

Custody gate: pass (no keys). The TVM executes read-only get-methods over proven,
read-only state; it does not sign, send, or hold anything. Its security surface is
execution fidelity (a wrong result misleads a consumer) and resource bounds (gas
and step limits against a hostile contract), both covered by tests.

## Verification

- The TVM reproduces get-method results exactly for a corpus of real mainnet
  accounts (wallet `seqno` and `get_public_key`, jetton `get_wallet_data`, DNS
  resolution, and a spread of common contracts), matched against the reference
  node.
- A get-method run over proven inputs yields the same result as the reference, and
  the API returns it as a trust-minimized type distinct from a `runSmcMethod`
  server response.
- Gas and step limits terminate a hostile or non-terminating get-method without
  hanging.
