//! Works out what a Simplex signature set actually signs, from captured bytes.
//!
//! Ed25519 verification is an exact oracle: a wrong guess at the message produces zero
//! valid signatures and the right one produces all of them, so the message format can
//! be established by trying candidates against a real set rather than by reading.

use sha2::{Digest, Sha256};
use sync_spike::check::tally;
use sync_spike::tl::{Link, Reader, SignatureSet};
use sync_spike::{block, sig};

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn main() {
    let path = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "captured/unverified-59379986.tl".to_string());
    let raw = std::fs::read(&path).expect("the captured reply");
    let proof = Reader::partial_block_proof(&raw).expect("it decodes");

    let link = proof
        .steps
        .iter()
        .find_map(|step| match step {
            Link::Forward(l) if matches!(l.set, SignatureSet::Simplex { .. }) => Some(l),
            _ => None,
        })
        .expect("a simplex link in the capture");

    let SignatureSet::Simplex {
        cc_seqno,
        validator_set_hash,
        signatures,
        session_id,
        slot,
        candidate,
    } = &link.set
    else {
        unreachable!()
    };

    println!("== the simplex set on the link to seqno {} ==\n", link.to.seqno);
    println!("  cc_seqno           {cc_seqno}");
    println!("  validator_set_hash {validator_set_hash}");
    println!("  session_id         {}", hex(session_id));
    println!("  slot               {slot}");
    println!("  signatures         {}", signatures.len());
    println!("  candidate          {} bytes", candidate.len());
    println!("    {}", hex(candidate));
    println!("  block root_hash    {}", hex(&link.to.root_hash));
    println!("  block file_hash    {}", hex(&link.to.file_hash));
    println!("  sha256(candidate)  {}", hex(&Sha256::digest(candidate)));

    // The candidate is a serialized consensus.CandidateHashData, so its first four
    // bytes name which form it is and the block id follows.
    if candidate.len() >= 4 {
        let id = u32::from_le_bytes(candidate[..4].try_into().unwrap());
        let name = match id {
            0xe8f9_bcdc => "consensus.candidateHashDataOrdinary",
            0x72b4_d933 => "consensus.candidateHashDataEmpty",
            _ => "unrecognised",
        };
        println!("  candidate is       {name} ({id:#010x})");
    }

    // The parent inside the candidate is itself a candidate id, which is what makes the
    // hash convention checkable: its shape is the shape this block's own id must have.
    let (parent_slot, parent_hash) = if candidate.len() >= 160 {
        let p = &candidate[candidate.len() - 44..];
        println!(
            "  parent             candidateParent {:#010x} / candidateId {:#010x}",
            u32::from_le_bytes(p[0..4].try_into().unwrap()),
            u32::from_le_bytes(p[4..8].try_into().unwrap())
        );
        let s = i32::from_le_bytes(p[8..12].try_into().unwrap());
        let h: [u8; 32] = p[12..44].try_into().unwrap();
        println!("    parent slot      {s}");
        println!("    parent hash      {}", hex(&h));
        (s, h)
    } else {
        (0, [0u8; 32])
    };
    let collated: [u8; 32] = candidate[4 + 80..4 + 80 + 32].try_into().unwrap();
    println!("  collated_file_hash {}", hex(&collated));

    let set = block::validator_set(&link.config_proof, &link.from.root_hash)
        .expect("the validator set for the link");
    println!(
        "\n  validator set: {} total, {} main, weight {}\n",
        set.total, set.main, set.total_weight
    );

    let sha_candidate: [u8; 32] = Sha256::digest(candidate).into();
    let hashes: Vec<(String, [u8; 32])> = vec![
        ("sha256(candidate)".into(), sha_candidate),
        ("root_hash".into(), link.to.root_hash),
        ("file_hash".into(), link.to.file_hash),
        ("collated_file_hash".into(), collated),
        ("parent_hash".into(), parent_hash),
        ("session_id".into(), *session_id),
    ];
    let slots: Vec<(String, i32)> = vec![
        ("slot".into(), *slot),
        ("slot+1".into(), slot + 1),
        ("parent_slot".into(), parent_slot),
        ("seqno".into(), link.to.seqno as i32),
    ];
    let votes: Vec<(String, u32)> = vec![
        ("finalize".into(), sig::FINALIZE_VOTE),
        ("notarize".into(), sig::NOTARIZE_VOTE),
        ("skip".into(), 0x2f6b_1f26),
    ];
    let prefixes: Vec<(String, Vec<u8>)> = vec![
        ("".into(), Vec::new()),
        ("session|".into(), session_id.to_vec()),
        ("cc|".into(), cc_seqno.to_le_bytes().to_vec()),
        (
            "session|cc|".into(),
            [session_id.as_slice(), &cc_seqno.to_le_bytes()].concat(),
        ),
    ];

    let mut tries: Vec<(String, Vec<u8>)> = Vec::new();
    // The forms that do not name a candidate at all, in case a Simplex set still signs
    // the block the way an ordinary one does.
    tries.push((
        "ton.blockId".into(),
        sig::signed_message(sig::TON_BLOCK_ID, &link.to.root_hash, &link.to.file_hash),
    ));
    tries.push((
        "ton.blockIdApprove".into(),
        sig::signed_message(
            sig::TON_BLOCK_ID_APPROVE,
            &link.to.root_hash,
            &link.to.file_hash,
        ),
    ));
    tries.push(("candidate raw".into(), candidate.clone()));

    for (pname, prefix) in &prefixes {
        for (sname, slot_value) in &slots {
            for (hname, hash) in &hashes {
                // A bare candidate id, a boxed one, and a boxed one inside each vote.
                let bare = [&slot_value.to_le_bytes()[..], hash].concat();
                let boxed = [&sig::CANDIDATE_ID.to_le_bytes()[..], &bare].concat();
                tries.push((
                    format!("{pname}candidateId[bare] {sname}/{hname}"),
                    [prefix.as_slice(), &bare].concat(),
                ));
                tries.push((
                    format!("{pname}candidateId {sname}/{hname}"),
                    [prefix.as_slice(), &boxed].concat(),
                ));
                for (vname, vote) in &votes {
                    tries.push((
                        format!("{pname}{vname}Vote {sname}/{hname}"),
                        [prefix.as_slice(), &vote.to_le_bytes(), &boxed].concat(),
                    ));
                    tries.push((
                        format!("dataToSign({vname}Vote {sname}/{hname})"),
                        sig::data_to_sign(
                            session_id,
                            &[&vote.to_le_bytes()[..], &boxed].concat(),
                        ),
                    ));
                    tries.push((
                        format!("{pname}{vname}Vote[bare id] {sname}/{hname}"),
                        [prefix.as_slice(), &vote.to_le_bytes(), &bare].concat(),
                    ));
                }
            }
        }
    }

    println!("  trying {} candidate messages\n", tries.len());
    let mut found = false;
    for (name, message) in &tries {
        let t = tally(link, &set, message);
        if t.valid > 0 {
            found = true;
            println!(
                "  MATCH  {name}  -> {} of {} valid, {:.1}% of weight, carries {}",
                t.valid,
                signatures.len(),
                t.share(set.total_weight) * 100.0,
                t.carries(set.total_weight)
            );
        }
    }
    if !found {
        println!("  nothing in the hypothesis space verified a single signature");
    }
}
