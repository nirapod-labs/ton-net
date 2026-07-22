<!--
SPDX-License-Identifier: Apache-2.0
SPDX-FileCopyrightText: 2026 Nirapod Labs
-->

# Governance

Who decides what, and how a decision is recorded. This is written down because a
project that says nothing about its governance is telling an adopter to guess,
and the guess is usually worse than the truth.

## The truth today

One maintainer, `athexweb3`, on behalf of Nirapod Labs, who holds the copyright.
There is no committee, no vote, and no second person with commit rights. The bus
factor is one.

That is stated rather than dressed up. An adopter evaluating whether to depend on
this library is entitled to know it, and a governance document describing a
structure that does not exist would be worse than none: it would be a claim the
project cannot honour.

## How a decision is made

Anything that constrains future work is written as an architecture decision
record in [`docs/adr/`](docs/adr/) before the code that depends on it. A record
carries the context, the options considered, the decision, and its consequences,
and it stays in the tree after it is superseded so the reasoning survives the
outcome.

The rule this exists to enforce is that a decision has a reason attached to it. A
maintainer who can be asked "why is it this way" and answers "it was already like
that" has lost something the next maintainer needs.

A record is `proposed` until it is `accepted`. Implementation follows acceptance,
not the other way around.

## How work is proposed

Through a pull request or an issue. Both are read. There is no separate process
for a contributor and a maintainer: the same review, the same checks, the same
requirement that a claim about behaviour is backed by a test.

Contribution mechanics are in [CONTRIBUTING.md](CONTRIBUTING.md).

## What is not open to change by pull request

Two things, because both are commitments rather than preferences.

**The trust model.** A read is verified against a block the client proved for
itself. A change that would let something be reported as verified without a proof
having checked out is refused regardless of what it buys, and no benchmark
argument reverses it.

**The license.** Apache-2.0, with the copyright held by Nirapod Labs and
contributions certified under the [Developer Certificate of
Origin](https://developercertificate.org/). Published history is never rewritten.

## If the maintainer stops

The library is Apache-2.0 and the whole design record is in the tree. A fork
carries the reasoning, not just the code, which is the point of writing the
records down. Nothing here requires the original author to be reachable.

## Becoming a maintainer

By sustained review-quality contribution, judged on whether the reasoning holds
up rather than on volume. There is no fixed threshold, because inventing one for
a project with a single maintainer would be theatre. If this changes, it changes
here first.
