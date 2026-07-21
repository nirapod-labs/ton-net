# ton-net-block

The block and account structures, and the proofs over them for [ton-net](https://github.com/nirapod-labs/ton-net), a direct TON
network client written once in Rust.

The TL-B for TON's block and account structures, decoded from cells, plus the
verification that makes a server's answer worth something: Merkle proof checking,
validator set derivation from a key block's own configuration, Ed25519 signature
checking, and block proof chain walking.

A lookup here distinguishes a proved absence from a withheld answer. Collapsing
the two would let a server deny that an account exists by staying silent.

## Using it

Most callers want the [`ton-net`](https://crates.io/crates/ton-net) facade rather
than this crate. It is the supported entry point, and it composes this layer with
the ones above and below it. Depending on this crate directly is supported and
reasonable when only this layer is needed.

## License

Apache-2.0. Copyright 2026 Nirapod Labs; maintained by athexweb3.
