//! A network test against a live mainnet liteserver.
//!
//! It is `#[ignore]` so the hermetic suite never reaches the network; the dedicated
//! network CI job runs it with `--ignored`. It completes a real ADNL handshake, asks a
//! liteserver for its masterchain head, and checks the answer is a plausible mainnet
//! one. This is the async counterpart to the byte vectors: those pin the layout, this
//! proves the layout still opens a session with a real node.

use std::time::Duration;

use ton_net_adnl::{AdnlConnection, TcpTransport};
use ton_net_tl::{deserialize, lite, serialize};

// One public mainnet liteserver and its Ed25519 key, from the feasibility spike. If this
// node is retired the test skips at connect; the network job can point at another.
const SERVER: &str = "5.9.10.47:19949";
const SERVER_KEY: &str = "9f85439d2094b92a639c2c9493d7b740e39dea8d08b525986d39d6dd69e7f309";

fn unhex32(s: &str) -> [u8; 32] {
    let mut out = [0u8; 32];
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).unwrap();
    }
    out
}

#[tokio::test]
#[ignore = "hits a live mainnet liteserver; run with --ignored in the network job"]
async fn reads_the_masterchain_head_from_mainnet() {
    let transport = match TcpTransport::connect(SERVER).await {
        Ok(transport) => transport,
        Err(e) => {
            eprintln!("skipping: {SERVER} unreachable: {e}");
            return;
        }
    };

    let mut conn = AdnlConnection::connect(transport, &unhex32(SERVER_KEY))
        .await
        .expect("handshake completes");

    // liteServer.query { liteServer.getMasterchainInfo }
    let query = serialize(lite::Query {
        data: serialize(lite::GetMasterchainInfo),
    });
    let answer = tokio::time::timeout(Duration::from_secs(10), conn.query(&query))
        .await
        .expect("answer arrives before the deadline")
        .expect("query succeeds");

    let info: lite::MasterchainInfo = deserialize(&answer).expect("answer decodes");
    assert_eq!(info.last.workchain, -1, "masterchain workchain");
    assert_eq!(info.last.shard, 0x8000_0000_0000_0000, "masterchain shard");
    assert!(info.last.seqno > 0, "masterchain seqno is live");
    eprintln!("mainnet masterchain seqno: {}", info.last.seqno);
}
