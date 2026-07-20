//! A network test of the read client against a live mainnet liteserver.
//!
//! `#[ignore]` so the hermetic suite never reaches the network; the network CI job runs
//! it with `--ignored`. It reads the masterchain head and the Elector account's state,
//! the two reads the facade exposes, over a real ADNL session.

use std::time::Duration;

use ton_net_adnl::TcpTransport;
use ton_net_lite::{AccountId, LiteClient};

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
async fn reads_the_masterchain_head_and_the_elector_account() {
    let transport = match TcpTransport::connect(SERVER).await {
        Ok(transport) => transport,
        Err(e) => {
            eprintln!("skipping: {SERVER} unreachable: {e}");
            return;
        }
    };

    let mut client = LiteClient::connect(transport, &unhex32(SERVER_KEY))
        .await
        .expect("handshake completes");

    let info = tokio::time::timeout(Duration::from_secs(10), client.masterchain_info())
        .await
        .expect("masterchain_info answers in time")
        .expect("masterchain_info succeeds");
    assert_eq!(info.value().last.workchain, -1, "masterchain workchain");
    assert_eq!(
        info.value().last.shard,
        0x8000_0000_0000_0000,
        "masterchain shard"
    );
    assert!(info.value().last.seqno > 0, "masterchain seqno is live");
    eprintln!("mainnet masterchain seqno: {}", info.value().last.seqno);

    // The Elector, -1:3333...3333, is a system contract that is always active.
    let elector = AccountId {
        workchain: -1,
        id: [0x33; 32],
    };
    let account = tokio::time::timeout(
        Duration::from_secs(10),
        client.account_state(&info.value().last, &elector),
    )
    .await
    .expect("account_state answers in time")
    .expect("account_state succeeds");
    assert!(
        !account.value().state.is_empty(),
        "the elector has a nonempty state"
    );
    eprintln!("elector state bytes: {}", account.value().state.len());
}
