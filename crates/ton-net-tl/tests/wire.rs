//! Wire-format tests for ton-net-tl.
//!
//! Three kinds of check: every boxed type's constructor id equals the CRC32 of its
//! TL scheme line; every type round-trips through serialize and deserialize; and the
//! exact query bytes match the layout a mainnet liteserver accepted in the
//! feasibility spike. A decode-robustness pass feeds arbitrary bytes to the
//! deserializers and requires that none panic.

use ton_net_tl::{adnl, deserialize, lite, serialize};

// IEEE CRC32, the TL constructor-id function. A boxed type's id is the CRC32 of its
// scheme line, written little-endian on the wire.
fn crc32(s: &str) -> u32 {
    let mut crc: u32 = 0xFFFF_FFFF;
    for &b in s.as_bytes() {
        crc ^= b as u32;
        for _ in 0..8 {
            let m = (crc & 1).wrapping_neg();
            crc = (crc >> 1) ^ (0xEDB8_8320 & m);
        }
    }
    !crc
}

fn first4(b: &[u8]) -> [u8; 4] {
    [b[0], b[1], b[2], b[3]]
}

fn block() -> lite::BlockIdExt {
    lite::BlockIdExt {
        workchain: -1,
        shard: 0x8000_0000_0000_0000,
        seqno: 42,
        root_hash: [0x11; 32],
        file_hash: [0x22; 32],
    }
}

fn masterchain_info() -> lite::MasterchainInfo {
    lite::MasterchainInfo {
        last: block(),
        state_root_hash: [0x33; 32],
        init: lite::ZeroStateIdExt {
            workchain: -1,
            root_hash: [0x44; 32],
            file_hash: [0x55; 32],
        },
    }
}

fn account_state() -> lite::AccountState {
    lite::AccountState {
        id: block(),
        shardblk: block(),
        shard_proof: vec![1, 2, 3],
        proof: vec![4, 5],
        state: vec![6, 7, 8, 9],
    }
}

#[test]
fn constructor_ids_match_scheme() {
    let cases: Vec<([u8; 4], &str)> = vec![
        (
            first4(&serialize(adnl::PublicKey { key: [0; 32] })),
            "pub.ed25519 key:int256 = PublicKey",
        ),
        (
            first4(&serialize(adnl::Message::Query { query_id: [0; 32], query: vec![] })),
            "adnl.message.query query_id:int256 query:bytes = adnl.Message",
        ),
        (
            first4(&serialize(adnl::Message::Answer { query_id: [0; 32], answer: vec![] })),
            "adnl.message.answer query_id:int256 answer:bytes = adnl.Message",
        ),
        (
            first4(&serialize(lite::Query { data: vec![] })),
            "liteServer.query data:bytes = Object",
        ),
        (
            first4(&serialize(lite::GetMasterchainInfo)),
            "liteServer.getMasterchainInfo = liteServer.MasterchainInfo",
        ),
        (first4(&serialize(lite::GetTime)), "liteServer.getTime = liteServer.CurrentTime"),
        (first4(&serialize(lite::GetVersion)), "liteServer.getVersion = liteServer.Version"),
        (
            first4(&serialize(lite::GetAccountState {
                id: block(),
                account: lite::AccountId { workchain: 0, id: [0; 32] },
            })),
            "liteServer.getAccountState id:tonNode.blockIdExt account:liteServer.accountId = liteServer.AccountState",
        ),
        (
            first4(&serialize(masterchain_info())),
            "liteServer.masterchainInfo last:tonNode.blockIdExt state_root_hash:int256 init:tonNode.zeroStateIdExt = liteServer.MasterchainInfo",
        ),
        (
            first4(&serialize(lite::CurrentTime { now: 0 })),
            "liteServer.currentTime now:int = liteServer.CurrentTime",
        ),
        (
            first4(&serialize(lite::Version { mode: 0, version: 0, capabilities: 0, now: 0 })),
            "liteServer.version mode:# version:int capabilities:long now:int = liteServer.Version",
        ),
        (
            first4(&serialize(account_state())),
            "liteServer.accountState id:tonNode.blockIdExt shardblk:tonNode.blockIdExt shard_proof:bytes proof:bytes state:bytes = liteServer.AccountState",
        ),
        (
            first4(&serialize(lite::Error { code: 0, message: Vec::new() })),
            "liteServer.error code:int message:string = liteServer.Error",
        ),
    ];
    for (got, scheme) in cases {
        assert_eq!(
            got,
            crc32(scheme).to_le_bytes(),
            "constructor id mismatch for `{scheme}`"
        );
    }
}

#[test]
fn types_round_trip() {
    let m = masterchain_info();
    assert_eq!(
        deserialize::<lite::MasterchainInfo>(&serialize(&m)).unwrap(),
        m
    );

    let a = account_state();
    assert_eq!(
        deserialize::<lite::AccountState>(&serialize(&a)).unwrap(),
        a
    );

    let q = adnl::Message::Query {
        query_id: [7; 32],
        query: vec![1, 2, 3, 4, 5],
    };
    assert_eq!(deserialize::<adnl::Message>(&serialize(&q)).unwrap(), q);

    let ans = adnl::Message::Answer {
        query_id: [9; 32],
        answer: vec![9, 9],
    };
    assert_eq!(deserialize::<adnl::Message>(&serialize(&ans)).unwrap(), ans);

    let e = lite::Error {
        code: -400,
        message: b"bad request".to_vec(),
    };
    assert_eq!(deserialize::<lite::Error>(&serialize(&e)).unwrap(), e);

    let v = lite::Version {
        mode: 0,
        version: 1,
        capabilities: 7,
        now: 1_700_000_000,
    };
    assert_eq!(deserialize::<lite::Version>(&serialize(&v)).unwrap(), v);

    let t = lite::CurrentTime { now: 1_700_000_000 };
    assert_eq!(deserialize::<lite::CurrentTime>(&serialize(&t)).unwrap(), t);
}

#[test]
fn query_wire_layout_matches_mainnet_spike() {
    // A nullary boxed request serializes to exactly its constructor id.
    assert_eq!(
        serialize(lite::GetMasterchainInfo),
        [0x2e, 0xe6, 0xb5, 0x89]
    );

    // The full getMasterchainInfo query the spike sent and a mainnet liteserver
    // accepted: adnl.message.query wrapping liteServer.query wrapping the method.
    let inner = serialize(lite::GetMasterchainInfo);
    let ls = serialize(lite::Query { data: inner });
    let qid = [0xAA_u8; 32];
    let msg = serialize(adnl::Message::Query {
        query_id: qid,
        query: ls,
    });

    let mut expect = Vec::new();
    expect.extend_from_slice(&[0x7a, 0xf9, 0x8b, 0xb4]); // adnl.message.query id
    expect.extend_from_slice(&qid);
    // liteServer.query (12 bytes: df068c79 + 04 2ee6b589 + 3 inner pad) as a TL
    // bytes field: length 0x0c, the 12 bytes, then 3 bytes of outer padding to the
    // 4-byte boundary.
    expect.extend_from_slice(&[
        0x0c, 0xdf, 0x06, 0x8c, 0x79, 0x04, 0x2e, 0xe6, 0xb5, 0x89, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00,
    ]);
    assert_eq!(msg, expect);
    assert_eq!(msg.len(), 52);
}

#[test]
fn decode_never_panics_on_arbitrary_bytes() {
    // A fixed-seed xorshift feeds pseudo-random byte strings to each deserializer.
    // A panic here fails the test; every input must resolve to Ok or Err.
    let mut s: u64 = 0x9E37_79B9_7F4A_7C15;
    let mut next = || {
        s ^= s << 13;
        s ^= s >> 7;
        s ^= s << 17;
        s
    };
    for _ in 0..50_000 {
        let n = (next() % 96) as usize;
        let buf: Vec<u8> = (0..n).map(|_| (next() & 0xff) as u8).collect();
        let _ = deserialize::<adnl::Message>(&buf);
        let _ = deserialize::<lite::MasterchainInfo>(&buf);
        let _ = deserialize::<lite::AccountState>(&buf);
        let _ = deserialize::<lite::Query>(&buf);
        let _ = deserialize::<lite::Error>(&buf);
    }
}

#[test]
fn hostile_length_prefix_is_rejected() {
    // liteServer.query id, then a bytes length prefix claiming ~16 MB with no data.
    // The decoder must reject the truncated input rather than trust the length.
    let mut buf = vec![0xdf, 0x06, 0x8c, 0x79];
    buf.extend_from_slice(&[0xfe, 0xff, 0xff, 0xff]);
    assert!(deserialize::<lite::Query>(&buf).is_err());
}

fn unhex(s: &str) -> Vec<u8> {
    (0..s.len() / 2)
        .map(|i| u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).unwrap())
        .collect()
}

// A real liteServer.masterchainInfo captured from a mainnet liteserver
// (5.9.10.47:19949) by the feasibility spike. Decoding it and re-encoding it must
// reproduce these exact bytes, which anchors the type layout to TON rather than to
// this crate's own encoder.
const MAINNET_MASTERCHAIN_INFO: &str = "81288385ffffffff00000000000000801721d3045fab3692062c45ef57802846943439f41ab442198c48e9c846274fa703e9efe8f1e0421cee64950897a206aa3f377355edc7bb96bb578f7a7381bf3ee7fb70e58455b4866a10724ac7d855dfbe2d73e4fab7a89a15a2c534dea37c87fa3a28aeffffffff17a3a92992aabea785a7a090985a265cd31f323d849da51239737e321fb055695e994fcf4d425c0a6ce6a792594b7173205f740a39cd56f537defd28b48a0f6e";

#[test]
fn decodes_a_real_mainnet_masterchain_info() {
    let bytes = unhex(MAINNET_MASTERCHAIN_INFO);
    let mc: lite::MasterchainInfo = deserialize(&bytes).expect("decode real response");

    assert_eq!(mc.last.workchain, -1);
    assert_eq!(mc.last.shard, 0x8000_0000_0000_0000);
    assert_eq!(mc.last.seqno, 80_945_431);
    assert_eq!(mc.init.workchain, -1);

    // Re-encoding the decoded value reproduces the server's exact bytes.
    assert_eq!(serialize(&mc), bytes);
}
