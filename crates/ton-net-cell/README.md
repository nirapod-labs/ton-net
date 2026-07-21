# ton-net-cell

The cell model and bag-of-cells codec for [ton-net](https://github.com/nirapod-labs/ton-net), a direct TON
network client written once in Rust.

TON's universal container: up to 1023 bits and up to four references per cell,
with representation hashing, level masks, and the exotic cells a Merkle proof is
built from.

This is the bottom of the stack and the first thing hostile bytes reach, so the
parser is written to refuse a malformed cell rather than to be generous with one.

## Using it

Most callers want the [`ton-net`](https://crates.io/crates/ton-net) facade rather
than this crate. It is the supported entry point, and it composes this layer with
the ones above and below it. Depending on this crate directly is supported and
reasonable when only this layer is needed.

## License

Apache-2.0. Copyright 2026 Nirapod Labs; maintained by athexweb3.
