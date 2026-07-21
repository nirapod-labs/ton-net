# ton-net-tl

The TL codec for [ton-net](https://github.com/nirapod-labs/ton-net), a direct TON
network client written once in Rust.

TON's TL wire format: CRC32-IEEE constructor tags, boxed and bare types, and the
schema types the liteserver protocol and ADNL exchange.

The tags are verified against the reference node rather than inferred, because one
wrong byte makes a request unanswerable and the failure looks like a network fault.

## Using it

Most callers want the [`ton-net`](https://crates.io/crates/ton-net) facade rather
than this crate. It is the supported entry point, and it composes this layer with
the ones above and below it. Depending on this crate directly is supported and
reasonable when only this layer is needed.

## License

Apache-2.0. Copyright 2026 Nirapod Labs; maintained by athexweb3.
