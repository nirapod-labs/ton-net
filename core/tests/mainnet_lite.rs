// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Nirapod Labs

//! A network test of the read client against a live mainnet liteserver.
//!
//! `#[ignore]` so the hermetic suite never reaches the network; the network CI job runs
//! it with `--ignored`. It reads the masterchain head and the Elector account's state,
//! the two reads the facade exposes, over a real ADNL session, and it offers one
//! deliberately unsendable message to see what a mainnet server makes of the request.

use std::fmt::Write as _;
use std::time::Duration;

use ton_net::adnl::{AdnlConnection, TcpTransport};
use ton_net::lite::{AccountId, LiteClient, LiteError};
use ton_net::tl::{lite, serialize};

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

fn hex(bytes: &[u8]) -> String {
    bytes.iter().fold(String::new(), |mut out, b| {
        let _ = write!(out, "{b:02x}");
        out
    })
}

/// Offers a body that is not a bag of cells and reports what mainnet answered.
///
/// Nothing is sent and no value moves: four bytes that cannot be parsed as a message
/// are refused before the server has anything to broadcast. The point of running it
/// against a live server is the half a scheme reading cannot settle. A constructor id
/// derived from the scheme is a hypothesis about what a server will call these bytes,
/// and the refusal being about the *body* rather than about the request is what says
/// the hypothesis was right, because a request whose id no server knows is refused
/// before any body is looked at.
///
/// The exchange it prints is the source of the constants the hermetic wire test in
/// `core/src/lite/client.rs` asserts against.
#[tokio::test]
#[ignore = "hits a live mainnet liteserver; run with --ignored in the network job"]
async fn a_mainnet_server_reads_the_send_request_and_refuses_the_body() {
    let transport = match TcpTransport::connect(SERVER).await {
        Ok(transport) => transport,
        Err(e) => {
            eprintln!("skipping: {SERVER} unreachable: {e}");
            return;
        }
    };

    // Driven one layer below `LiteClient` so the answer bytes are visible. What the
    // client would do with them is the assertion underneath.
    let mut connection = AdnlConnection::connect(transport, &unhex32(SERVER_KEY))
        .await
        .expect("handshake completes");

    let body = vec![0xde, 0xad, 0xbe, 0xef];
    let request = serialize(lite::SendMessage { body: body.clone() });
    let query = serialize(lite::Query {
        data: request.clone(),
    });
    let answer = tokio::time::timeout(Duration::from_secs(10), connection.query(&query))
        .await
        .expect("sendMessage answers in time")
        .expect("the query completes");

    eprintln!("mainnet sendMessage request: {}", hex(&request));
    eprintln!("mainnet sendMessage answer:  {}", hex(&answer));

    let error = ton_net::tl::deserialize::<lite::Error>(&answer)
        .expect("an unsendable body is refused, so the answer is a liteServer.error");
    let message = String::from_utf8_lossy(&error.message);
    assert!(
        message.contains("ext-message") || message.contains("external message"),
        "the refusal names the message rather than the request: {message}"
    );

    // The same exchange through the client, which is the path a caller takes.
    let transport = TcpTransport::connect(SERVER).await.expect("reconnects");
    let mut client = LiteClient::connect(transport, &unhex32(SERVER_KEY))
        .await
        .expect("handshake completes");
    let result = tokio::time::timeout(Duration::from_secs(10), client.send_message(&body))
        .await
        .expect("sendMessage answers in time");
    assert!(
        matches!(result, Err(LiteError::LiteServer { .. })),
        "a refused body is a plain server error, not a duplicate: {result:?}"
    );
}
