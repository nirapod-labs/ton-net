# ton-net-adnl

The ADNL transport for [ton-net](https://github.com/nirapod-labs/ton-net), a direct TON
network client written once in Rust.

TON's ADNL protocol over TCP: the handshake, the session key derivation, and the
encrypted stream framing a liteserver connection runs on.

The protocol logic is sans-I/O over a transport trait. Today the one implementation
is tokio TCP; the seam exists so a browser, which cannot open a raw socket, can
supply a WebSocket instead without the protocol code knowing.

## Using it

Most callers want the [`ton-net`](https://crates.io/crates/ton-net) facade rather
than this crate. It is the supported entry point, and it composes this layer with
the ones above and below it. Depending on this crate directly is supported and
reasonable when only this layer is needed.

## License

Apache-2.0. Copyright 2026 Nirapod Labs; maintained by athexweb3.
