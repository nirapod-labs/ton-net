// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Nirapod Labs

//! Starts from a block the caller chose, so the bundled configuration is not trusted.
//!
//! ```text
//! cargo run --example own_anchor
//! ```
//!
//! The library's readme lists two things still taken on trust, and this removes the
//! first of them. `Config::mainnet` carries an init block, and everything a client goes
//! on to prove is measured against it, so whoever chose that block chose the root of
//! trust. Supplying one instead moves that choice to the caller.
//!
//! A block identity worth pinning is one confirmed from somewhere the caller already
//! trusts: an explorer they run, a second implementation, or an earlier run of their own
//! that they recorded. Copying the numbers below from a stranger just moves the same
//! question to a different stranger.

use ton_net::{Address, BlockIdExt, Client, Config, Error};

#[tokio::main]
async fn main() -> Result<(), Error> {
    let config = Config::mainnet();

    // What the configuration would have used, shown so the two can be compared. A caller
    // supplying their own does not need this call.
    match config.init_block() {
        Some(pinned) => println!("the configuration pins block {}", pinned.seqno),
        None => println!("the configuration pins no block"),
    }

    // The same block, named explicitly. Substituting a different one is the whole point
    // of the example: this is where a caller's own trusted identity goes.
    let mine = BlockIdExt::new(
        -1,
        0x8000_0000_0000_0000,
        46_894_135,
        base64(b"MEjmmhLPlG68mbTPnKYcP/Sz/MiMQBV2OsASBOzBv58=")?,
        base64(b"u9rAtFQ+kUFEnOs3w8Y7punMTiyQTXf1bRfkSs8dG+0=")?,
    );
    println!("walking from block {} instead", mine.seqno);

    let mut client = Client::connect_from(&config, &mine).await?;
    let report = client.sync().await?;
    println!("proved {} links, head {}", report.links, report.head.seqno);

    let elector =
        Address::parse("-1:3333333333333333333333333333333333333333333333333333333333333333")?;
    let account = client.account(&elector).await?;
    println!("balance {}", account.value().balance);

    Ok(())
}

/// Decodes one standard base64 block hash. The library takes hashes as bytes, and a
/// block identity is usually written down in base64, so something has to bridge the two.
fn base64(text: &[u8]) -> Result<[u8; 32], Error> {
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = Vec::with_capacity(32);
    let mut acc: u32 = 0;
    let mut bits = 0;
    for byte in text.iter().copied().filter(|b| *b != b'=') {
        let value = ALPHABET
            .iter()
            .position(|c| *c == byte)
            .ok_or_else(|| Error::Config(format!("not base64: {byte}")))?;
        acc = (acc << 6) | value as u32;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
        }
    }
    out.try_into()
        .map_err(|_| Error::Config("a block hash is 32 bytes".to_owned()))
}
