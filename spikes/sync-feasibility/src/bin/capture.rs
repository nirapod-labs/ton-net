//! Captures one whole reply per signed form, small enough to live in the repo.
//!
//! The walk's own captures are whole 700 kB replies carrying sixteen links each. The
//! library's codec tests want a real reply they can round-trip byte for byte, so this
//! asks for the shortest proof there is: from a key block to the very next one, which
//! the server answers with a single forward link.
//!
//! The two endpoints come from the walk's captures rather than from guesswork, one pair
//! from either side of the block where mainnet changed its signed form.

use std::time::Duration;

use ton_net_adnl::{AdnlConnection, TcpTransport};
use ton_net_tl::{lite as wire, serialize};

use sync_spike::tl::{self, BlockIdExt, Link, Reader};

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

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn unhex(s: &str) -> [u8; 32] {
    let mut out = [0u8; 32];
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).expect("hex");
    }
    out
}

/// Pulls the endpoints of one forward link out of a captured reply.
fn endpoints(path: &str, simplex: bool) -> (BlockIdExt, BlockIdExt) {
    let raw = std::fs::read(path).unwrap_or_else(|e| panic!("{path}: {e}"));
    let proof = Reader::partial_block_proof(&raw).expect("the capture decodes");
    let link = proof
        .steps
        .iter()
        .find_map(|step| match step {
            Link::Forward(l)
                if matches!(l.set, tl::SignatureSet::Simplex { .. }) == simplex
                    && l.to_key_block =>
            {
                Some(l)
            }
            _ => None,
        })
        .unwrap_or_else(|| panic!("{path} has no such link"));
    (link.from.clone(), link.to.clone())
}

async fn connect() -> AdnlConnection<TcpTransport> {
    for (addr, key) in LITESERVERS {
        let attempt = async {
            let transport = TcpTransport::connect(addr).await.ok()?;
            AdnlConnection::connect(transport, &unhex(key)).await.ok()
        };
        if let Ok(Some(connection)) = tokio::time::timeout(Duration::from_secs(15), attempt).await {
            println!("  connected to {addr}");
            return connection;
        }
        eprintln!("  skipping {addr}");
    }
    panic!("no liteserver reachable");
}

#[tokio::main]
async fn main() {
    let mut connection = connect().await;

    for (name, source, simplex) in [
        ("ordinary", "captured/chain-round-1.tl", false),
        ("simplex", "captured/unverified-59379986.tl", true),
    ] {
        let (known, target) = endpoints(source, simplex);
        let envelope = serialize(wire::Query {
            data: tl::get_block_proof(&known, &target),
        });
        let answer = tokio::time::timeout(Duration::from_secs(45), connection.query(&envelope))
            .await
            .expect("the query times out")
            .expect("the query fails");

        let proof = Reader::partial_block_proof(&answer).expect("the answer decodes");
        let form = match proof.steps.first() {
            Some(Link::Forward(l)) => l.set.kind(),
            _ => "none",
        };
        println!(
            "  {name:>8}: {} steps, {} B, {} -> {}, form {form}, complete {}",
            proof.steps.len(),
            answer.len(),
            proof.from.seqno,
            proof.to.seqno,
            proof.complete,
        );

        let path = format!("captured/one-link-{name}.hex");
        std::fs::write(&path, hex(&answer)).expect("write the fixture");
        println!("           written to {path}");
    }
}
