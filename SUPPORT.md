<!--
SPDX-License-Identifier: Apache-2.0
SPDX-FileCopyrightText: 2026 Nirapod Labs
-->

# Support

Where a question goes, so that it reaches somewhere it can be answered.

| the thing at hand | where it goes |
| --- | --- |
| A bug, or behaviour that contradicts the documentation | [an issue](https://github.com/nirapod-labs/ton-net/issues) |
| A vulnerability | **not an issue.** [SECURITY.md](SECURITY.md), through GitHub's private reporting |
| A question about how something works | an issue, and it is welcome |
| A missing feature | an issue describing the goal, not only the addition |
| A change already written | [a pull request](https://github.com/nirapod-labs/ton-net/pulls), see [CONTRIBUTING.md](CONTRIBUTING.md) |

A question filed as an issue is not a misuse of the tracker here. If the answer
turns out to be in the documentation, then the documentation was not clear
enough, and that is worth an issue of its own.

## What makes a report answerable

The version, the platform, and what actually happened. For anything touching the
network, the error in full: its message opens with a prefix naming the layer that
failed, and that prefix is what decides where the answer lies.

A sync or a proof failure is more useful with the block the client was working
from. `Client::anchor` in Rust and `client.anchor()` in Node return it.

## What to expect

One maintainer, no service commitment, and no guaranteed response time. A
security report is the exception and carries its own timeline in
[SECURITY.md](SECURITY.md).

Stated plainly: this is a library published in the open rather than a supported
product, and nothing here promises support. What is promised is that a bug in
proof verification is treated as serious, because that is the class of failure
the library exists to prevent.

## Documentation

The API reference is the rustdoc, buildable with `cargo doc --open` and published
to docs.rs at the first release. The design records are in
[`docs/adr/`](docs/adr/), and the wire-format map and the conformance vectors are
in [`docs/`](docs/).
