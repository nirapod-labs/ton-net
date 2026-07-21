// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Nirapod Labs

//! Wire-format tests for ton-net-tl.
//!
//! Three kinds of check: every boxed type's constructor id equals the CRC32 of its
//! TL scheme line; every type round-trips through serialize and deserialize; and the
//! exact query bytes match the layout a mainnet liteserver accepted in the
//! feasibility spike. A decode-robustness pass feeds arbitrary bytes to the
//! deserializers and requires that none panic.
//!
//! The block-proof types are anchored harder than that. Two whole answers a mainnet
//! liteserver gave, one per signed form, are decoded and re-encoded and must come back
//! byte for byte, which pins the layout to TON rather than to this crate's encoder.

use ton_net_tl::{adnl, deserialize, lite, serialize, signed, TlError};

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

fn get_block_proof() -> lite::GetBlockProof {
    lite::GetBlockProof {
        mode: (),
        known_block: block(),
        target_block: Some(block()),
    }
}

fn signature() -> lite::Signature {
    lite::Signature {
        node_id_short: [0x66; 32],
        signature: vec![0x77; 64],
    }
}

fn ordinary_set() -> lite::SignatureSet {
    lite::SignatureSet::Ordinary {
        validator_set_hash: 111,
        catchain_seqno: 222,
        signatures: vec![signature()],
    }
}

fn simplex_set() -> lite::SignatureSet {
    lite::SignatureSet::Simplex {
        cc_seqno: 333,
        validator_set_hash: 444,
        signatures: vec![signature(), signature()],
        session_id: [0x88; 32],
        slot: 555,
        candidate: vec![0x99; 40],
    }
}

fn forward_link() -> lite::BlockLink {
    lite::BlockLink::Forward {
        to_key_block: true,
        from: block(),
        to: block(),
        dest_proof: vec![1, 2, 3],
        config_proof: vec![4, 5],
        signatures: ordinary_set(),
    }
}

fn back_link() -> lite::BlockLink {
    lite::BlockLink::Back {
        to_key_block: false,
        from: block(),
        to: block(),
        dest_proof: vec![1],
        proof: vec![2, 3],
        state_proof: vec![4, 5, 6],
    }
}

fn partial_block_proof() -> lite::PartialBlockProof {
    lite::PartialBlockProof {
        complete: true,
        from: block(),
        to: block(),
        steps: vec![forward_link(), back_link()],
    }
}

fn candidate_id() -> signed::CandidateId {
    signed::CandidateId {
        slot: 7,
        hash: [0xcd; 32],
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
        (
            first4(&serialize(get_block_proof())),
            "liteServer.getBlockProof mode:# known_block:tonNode.blockIdExt target_block:mode.0?tonNode.blockIdExt = liteServer.PartialBlockProof",
        ),
        (
            first4(&serialize(partial_block_proof())),
            "liteServer.partialBlockProof complete:Bool from:tonNode.blockIdExt to:tonNode.blockIdExt steps:vector liteServer.BlockLink = liteServer.PartialBlockProof",
        ),
        (
            first4(&serialize(forward_link())),
            "liteServer.blockLinkForward to_key_block:Bool from:tonNode.blockIdExt to:tonNode.blockIdExt dest_proof:bytes config_proof:bytes signatures:liteServer.SignatureSet = liteServer.BlockLink",
        ),
        (
            first4(&serialize(back_link())),
            "liteServer.blockLinkBack to_key_block:Bool from:tonNode.blockIdExt to:tonNode.blockIdExt dest_proof:bytes proof:bytes state_proof:bytes = liteServer.BlockLink",
        ),
        // The ordinary set's scheme line carries an explicit id rather than computing
        // one, and the id it carries is what the older unnamed line below computes to.
        // Checking against that line is what shows the two are the same wire form.
        (
            first4(&serialize(ordinary_set())),
            "liteServer.signatureSet validator_set_hash:int catchain_seqno:int signatures:vector liteServer.signature = liteServer.SignatureSet",
        ),
        (
            first4(&serialize(simplex_set())),
            "liteServer.signatureSet.simplex cc_seqno:int validator_set_hash:int signatures:vector liteServer.signature session_id:int256 slot:int candidate:bytes = liteServer.SignatureSet",
        ),
        (
            first4(&serialize(signed::BlockId { root_cell_hash: [0; 32], file_hash: [0; 32] })),
            "ton.blockId root_cell_hash:int256 file_hash:int256 = ton.BlockId",
        ),
        (
            first4(&serialize(signed::BlockIdApprove { root_cell_hash: [0; 32], file_hash: [0; 32] })),
            "ton.blockIdApprove root_cell_hash:int256 file_hash:int256 = ton.BlockId",
        ),
        (
            first4(&serialize(candidate_id())),
            "consensus.candidateId slot:int hash:int256 = consensus.CandidateId",
        ),
        (
            first4(&serialize(signed::Vote::Notarize { id: candidate_id() })),
            "consensus.simplex.notarizeVote id:consensus.CandidateId = consensus.simplex.UnsignedVote",
        ),
        (
            first4(&serialize(signed::Vote::Finalize { id: candidate_id() })),
            "consensus.simplex.finalizeVote id:consensus.CandidateId = consensus.simplex.UnsignedVote",
        ),
        (
            first4(&serialize(signed::DataToSign { session_id: [0; 32], data: Vec::new() })),
            "consensus.dataToSign session_id:int256 data:bytes = consensus.DataToSign",
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

    let p = partial_block_proof();
    assert_eq!(
        deserialize::<lite::PartialBlockProof>(&serialize(&p)).unwrap(),
        p
    );

    for set in [ordinary_set(), simplex_set()] {
        assert_eq!(
            deserialize::<lite::SignatureSet>(&serialize(&set)).unwrap(),
            set
        );
    }

    let d = signed::DataToSign {
        session_id: [0xab; 32],
        data: serialize(signed::Vote::Finalize { id: candidate_id() }),
    };
    assert_eq!(
        deserialize::<signed::DataToSign>(&serialize(&d)).unwrap(),
        d
    );
    assert_eq!(
        deserialize::<signed::Vote>(&d.data).unwrap(),
        signed::Vote::Finalize { id: candidate_id() }
    );
}

#[test]
fn the_mode_word_follows_the_target_block() {
    // `mode` is not carried on the struct, it is derived, so the flag word and the
    // field it describes cannot disagree. Bit 0 says a target block follows.
    let with = serialize(get_block_proof());
    assert_eq!(with[4..8], [1, 0, 0, 0]);
    assert_eq!(with.len(), 4 + 4 + 80 + 80);

    let without = serialize(lite::GetBlockProof {
        mode: (),
        known_block: block(),
        target_block: None,
    });
    assert_eq!(without[4..8], [0, 0, 0, 0]);
    assert_eq!(without.len(), 4 + 4 + 80);

    assert_eq!(
        deserialize::<lite::GetBlockProof>(&with).unwrap(),
        get_block_proof()
    );
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
        let _ = deserialize::<lite::PartialBlockProof>(&buf);
        let _ = deserialize::<lite::BlockLink>(&buf);
        let _ = deserialize::<lite::SignatureSet>(&buf);
        let _ = deserialize::<lite::GetBlockProof>(&buf);
        let _ = deserialize::<signed::Vote>(&buf);
        let _ = deserialize::<signed::DataToSign>(&buf);
    }
}

#[test]
fn a_hostile_vector_length_does_not_allocate() {
    // A signature set claiming four billion signatures, with none of them present.
    // The decoder must bound the count by what is left in the packet rather than
    // reserving for the claim.
    let mut buf = 0xf644_a6e6_u32.to_le_bytes().to_vec();
    buf.extend_from_slice(&1i32.to_le_bytes());
    buf.extend_from_slice(&2i32.to_le_bytes());
    buf.extend_from_slice(&u32::MAX.to_le_bytes());
    assert!(deserialize::<lite::SignatureSet>(&buf).is_err());

    // The same claim on the steps vector of a whole answer.
    let mut buf = 0x8ed0_d2c1_u32.to_le_bytes().to_vec();
    buf.extend_from_slice(&0x9972_75b5_u32.to_le_bytes());
    buf.extend_from_slice(&serialize(block())[..]);
    buf.extend_from_slice(&serialize(block())[..]);
    buf.extend_from_slice(&u32::MAX.to_le_bytes());
    assert!(deserialize::<lite::PartialBlockProof>(&buf).is_err());
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

/// A whole answer to `liteServer.getBlockProof`: one forward link from the block the
/// mainnet config pins, signed in the older form.
const ORDINARY_PROOF: &str = include_str!("fixtures/one-link-ordinary.hex");

/// The same, one link across the block where mainnet changed its signed form.
const SIMPLEX_PROOF: &str = include_str!("fixtures/one-link-simplex.hex");

/// Reads a fixture, dropping the provenance header and the line breaks.
fn fixture(text: &str) -> Vec<u8> {
    let hex: String = text
        .lines()
        .filter(|line| !line.starts_with('#'))
        .flat_map(str::chars)
        .filter(|c| !c.is_whitespace())
        .collect();
    unhex(&hex)
}

/// The offset of the only occurrence of `needle`, so a test can patch a field without
/// hard-coding an offset that a re-captured fixture would move.
fn only_at(haystack: &[u8], needle: &[u8]) -> usize {
    let found: Vec<usize> = haystack
        .windows(needle.len())
        .enumerate()
        .filter(|(_, w)| *w == needle)
        .map(|(i, _)| i)
        .collect();
    assert_eq!(found.len(), 1, "expected one occurrence, found {found:?}");
    found[0]
}

#[test]
fn a_captured_block_proof_round_trips_byte_for_byte() {
    for (name, text) in [("ordinary", ORDINARY_PROOF), ("simplex", SIMPLEX_PROOF)] {
        let bytes = fixture(text);
        let proof: lite::PartialBlockProof =
            deserialize(&bytes).unwrap_or_else(|e| panic!("{name} fixture does not decode: {e}"));

        assert!(proof.complete, "{name}: the server said the chain is short");
        assert_eq!(proof.steps.len(), 1, "{name}: expected a single step");
        assert_eq!(proof.from.workchain, -1);
        assert_eq!(proof.to.workchain, -1);
        assert!(proof.to.seqno > proof.from.seqno);

        // Re-encoding what was decoded reproduces the server's exact bytes. A field
        // read at the wrong width or in the wrong order cannot survive this.
        assert_eq!(serialize(&proof), bytes, "{name}: re-encode differs");
    }
}

#[test]
fn the_captures_cover_both_signed_forms() {
    // A round-trip proves the layout is self-consistent, not that the fixtures are
    // what they claim to be. This is what makes the pair meaningful.
    let ordinary: lite::PartialBlockProof = deserialize(&fixture(ORDINARY_PROOF)).unwrap();
    let simplex: lite::PartialBlockProof = deserialize(&fixture(SIMPLEX_PROOF)).unwrap();

    let set = |proof: &lite::PartialBlockProof| match &proof.steps[0] {
        lite::BlockLink::Forward {
            to_key_block,
            signatures,
            ..
        } => {
            assert!(to_key_block, "both links should end at a key block");
            signatures.clone()
        }
        other => panic!("expected a forward link, got {other:?}"),
    };

    match set(&ordinary) {
        lite::SignatureSet::Ordinary { signatures, .. } => assert!(!signatures.is_empty()),
        other => panic!("the ordinary capture holds {other:?}"),
    }
    match set(&simplex) {
        lite::SignatureSet::Simplex {
            signatures,
            candidate,
            ..
        } => {
            assert!(!signatures.is_empty());
            assert!(!candidate.is_empty(), "a vote with no candidate");
        }
        other => panic!("the simplex capture holds {other:?}"),
    }
}

#[test]
fn an_unknown_signature_set_is_refused_rather_than_read() {
    let mut bytes = fixture(SIMPLEX_PROOF);
    let at = only_at(&bytes, &0xac24_9800_u32.to_le_bytes());
    bytes[at..at + 4].copy_from_slice(&0xdead_beef_u32.to_le_bytes());

    // The fields after the id are untouched and still well formed, so a decoder that
    // guessed at the constructor would read them and return a set the server never
    // sent. Refusing by name is what stops that.
    assert!(matches!(
        deserialize::<lite::PartialBlockProof>(&bytes),
        Err(TlError::UnknownConstructor)
    ));
}

#[test]
fn an_unknown_block_link_is_refused_rather_than_read() {
    let mut bytes = fixture(ORDINARY_PROOF);
    let at = only_at(&bytes, &0x520f_ce1c_u32.to_le_bytes());
    bytes[at..at + 4].copy_from_slice(&0xdead_beef_u32.to_le_bytes());

    assert!(matches!(
        deserialize::<lite::PartialBlockProof>(&bytes),
        Err(TlError::UnknownConstructor)
    ));
}

#[test]
fn the_set_id_is_the_only_thing_keeping_the_two_forms_apart() {
    // The two forms open with the same two integers in the opposite order, so a set
    // relabelled as the other decodes cleanly with its fields swapped. Nothing later
    // in the bytes catches it. This is what the union is for, and the reason a third
    // form has to be a named failure rather than a best guess.
    let bytes = fixture(SIMPLEX_PROOF);
    let at = only_at(&bytes, &0xac24_9800_u32.to_le_bytes());

    let mut relabelled = bytes[at..].to_vec();
    relabelled[..4].copy_from_slice(&0xf644_a6e6_u32.to_le_bytes());

    let (cc_seqno, validator_set_hash) = match deserialize::<lite::SignatureSet>(&bytes[at..]) {
        Ok(lite::SignatureSet::Simplex {
            cc_seqno,
            validator_set_hash,
            ..
        }) => (cc_seqno, validator_set_hash),
        other => panic!("the capture holds {other:?}"),
    };

    match deserialize::<lite::SignatureSet>(&relabelled) {
        Ok(lite::SignatureSet::Ordinary {
            validator_set_hash: first,
            catchain_seqno: second,
            ..
        }) => {
            assert_eq!(first, cc_seqno);
            assert_eq!(second, validator_set_hash);
        }
        other => panic!("expected a silently swapped read, got {other:?}"),
    }
}
