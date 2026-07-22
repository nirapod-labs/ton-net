// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Nirapod Labs

//! Captures one whole block, which is the only place a complete augmented dictionary
//! can be found.
//!
//! Every fixture in the tree so far is a Merkle proof, and a proof is a chain: it shows
//! the one path it was asked about and prunes every sibling. Measured over the three
//! captured account reads, not one of their 75 dictionary forks has both children
//! visible. That is fine for reading, and it is useless as evidence about an augmented
//! dictionary, whose whole content is that a fork's extra summarises the two subtrees
//! below it.
//!
//! A block is not a proof. Nothing in it is pruned, so its `account_blocks` is a
//! complete `HashmapAugE 256 AccountBlock CurrencyCollection`, and each account block
//! holds a complete `HashmapAug 64 ^Transaction CurrencyCollection`. Both combine by
//! adding currency collections, which is a rule a rebuilt dictionary either reproduces
//! to the block's own hash or does not.
//!
//! ```text
//! cargo run --bin capture-block
//! ```
//!
//! It reports what each candidate holds and writes the one worth pinning. The root hash
//! it prints is the server's own word; confirm it elsewhere before trusting it.

use std::time::Duration;

use ton_net_adnl::{AdnlConnection, TcpTransport};
use ton_net_tl::{lite as wire, serialize};

use sync_spike::tl::{BlockIdExt, Reader};

const LITESERVERS: &[(&str, &str)] = &[
    (
        "5.9.10.47:19949",
        "9f85439d2094b92a639c2c9493d7b740e39dea8d08b525986d39d6dd69e7f309",
    ),
    (
        "5.9.10.15:48014",
        "dd73baecafea8be82edd3f6ff06da1c75c8d99666171c2f73bb4a8a2c168f06d",
    ),
];

/// `liteServer.getMasterchainInfo = liteServer.MasterchainInfo`
const GET_MASTERCHAIN_INFO: u32 = 0x89b5_e62e;
/// `liteServer.getBlock id:tonNode.blockIdExt = liteServer.BlockData`
const GET_BLOCK: u32 = 0x6377_cf0d;
/// `liteServer.blockData id:tonNode.blockIdExt data:bytes = liteServer.BlockData`
const BLOCK_DATA: u32 = 0xa574_ed6c;
/// `liteServer.getAccountState id:tonNode.blockIdExt account:liteServer.accountId
///  = liteServer.AccountState`
const GET_ACCOUNT_STATE: u32 = 0x6b89_0e25;

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn unhex32(s: &str) -> [u8; 32] {
    let mut out = [0u8; 32];
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).expect("hex");
    }
    out
}

fn get_block(id: &BlockIdExt) -> Vec<u8> {
    let mut out = GET_BLOCK.to_le_bytes().to_vec();
    id.write(&mut out);
    out
}

fn get_account_state(block: &BlockIdExt, workchain: i32, account: &[u8; 32]) -> Vec<u8> {
    let mut out = GET_ACCOUNT_STATE.to_le_bytes().to_vec();
    block.write(&mut out);
    out.extend_from_slice(&workchain.to_le_bytes());
    out.extend_from_slice(account);
    out
}

async fn connect() -> AdnlConnection<TcpTransport> {
    for (addr, key) in LITESERVERS {
        let attempt = async {
            let transport = TcpTransport::connect(addr).await.ok()?;
            AdnlConnection::connect(transport, &unhex32(key)).await.ok()
        };
        if let Ok(Some(connection)) = tokio::time::timeout(Duration::from_secs(15), attempt).await {
            println!("  connected to {addr}");
            return connection;
        }
        eprintln!("  skipping {addr}");
    }
    panic!("no liteserver reachable");
}

async fn ask(connection: &mut AdnlConnection<TcpTransport>, data: Vec<u8>) -> Vec<u8> {
    let envelope = serialize(wire::Query { data });
    tokio::time::timeout(Duration::from_secs(60), connection.query(&envelope))
        .await
        .expect("the query times out")
        .expect("the query fails")
}

/// Reads a `liteServer.blockData` answer.
fn block_data(bytes: &[u8]) -> (BlockIdExt, Vec<u8>) {
    let mut reader = Reader::new(bytes);
    let tag = reader.u32().expect("a tag");
    assert_eq!(tag, BLOCK_DATA, "answer was {tag:#x}, not a block");
    let id = reader.block_id().expect("a block id");
    let data = reader.tl_bytes().expect("the block bytes");
    (id, data)
}

#[tokio::main]
async fn main() {
    let mut connection = connect().await;

    // The head, and the shard block that head names for a basechain account. A
    // masterchain block touches a handful of accounts; a basechain one touches enough
    // for the dictionary to have forks worth checking.
    let answer = ask(&mut connection, GET_MASTERCHAIN_INFO.to_le_bytes().to_vec()).await;
    let mut reader = Reader::new(&answer);
    let tag = reader.u32().expect("a tag");
    assert_eq!(tag, 0x8583_2881, "not a masterchain info answer");
    let head = reader.block_id().expect("the head");
    println!("  head {head}");

    // Any deployed basechain address will do; this is the one the read fixtures use.
    let account = unhex32("b113a994b5024a16719f69139328eb759596c38a25f59028b146fecdc3621dfe");
    let answer = ask(&mut connection, get_account_state(&head, 0, &account)).await;
    let mut reader = Reader::new(&answer);
    let tag = reader.u32().expect("a tag");
    assert_eq!(
        tag, 0x7079_c751,
        "answer was {tag:#x}, not an account state"
    );
    let _at = reader.block_id().expect("the block");
    let shard = reader.block_id().expect("the shard block");
    println!("  shard block {shard}");

    for (what, id) in [("masterchain", &head), ("basechain", &shard)] {
        let answer = ask(&mut connection, get_block(id)).await;
        let (got, data) = block_data(&answer);
        println!(
            "  {what:>12}: {} seqno {} -> {} bytes of block",
            got,
            got.seqno,
            data.len()
        );
        let path = format!(
            "{}/captured/block-{what}-{}.boc",
            env!("CARGO_MANIFEST_DIR"),
            got.seqno
        );
        std::fs::write(&path, &data).expect("the fixture writes");
        println!(
            "                wrote {path}\n                root_hash={}\n                file_hash={}",
            hex(&got.root_hash),
            hex(&got.file_hash)
        );
    }
}
