# ton-net-lite

The liteserver query layer for [ton-net](https://github.com/nirapod-labs/ton-net), a direct TON
network client written once in Rust.

The liteserver protocol: requests, responses, and the error shapes a TON
liteserver answers with, over an ADNL connection.

What comes back is what the server said. Verifying it against a block is
`ton-net-block`'s job, and the types here keep the two apart.

## Using it

Most callers want the [`ton-net`](https://crates.io/crates/ton-net) facade rather
than this crate. It is the supported entry point, and it composes this layer with
the ones above and below it. Depending on this crate directly is supported and
reasonable when only this layer is needed.

## License

Apache-2.0. Copyright 2026 Nirapod Labs; maintained by athexweb3.
