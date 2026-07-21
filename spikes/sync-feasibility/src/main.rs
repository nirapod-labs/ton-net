//! Block-sync feasibility spike.
//!
//! Answers the questions the v0.3.0 plan cannot answer by reading, against live
//! mainnet. See the README for what each stage establishes.

use std::time::{Duration, Instant};

use ton_net_adnl::{AdnlConnection, TcpTransport};
use ton_net_tl::{lite as wire, serialize};

use sync_spike::check::{candidate_messages, report_messages, tally};
use sync_spike::{block, tl};
use tl::{BlockIdExt, Link, PartialBlockProof, Reader};

/// `liteServer.getMasterchainInfo`, read by hand so one connection serves every query.
const GET_MASTERCHAIN_INFO: u32 = 0x89b5_e62e;
const MASTERCHAIN_INFO: u32 = 0x8583_2881;

/// The masterchain shard, which is the whole address space.
const MASTERCHAIN_SHARD: u64 = 0x8000_0000_0000_0000;

/// Liteservers from the bundled mainnet config, tried in order.
const LITESERVERS: &[(&str, &str)] = &[
    (
        "5.9.10.47:19949",
        "9f85439d2094b92a639c2c9493d7b740e39dea8d08b525986d39d6dd69e7f309",
    ),
    (
        "5.9.10.15:48014",
        "dd73baecafea8be82edd3f6ff06da1c75c8d99666171c2f73bb4a8a2c168f06d",
    ),
    (
        "135.181.177.59:53312",
        "685f750ae507bae3aff6b9b65b9f8eff8877f0cdec466e340ed49d4714219ad4",
    ),
    (
        "135.181.140.212:13206",
        "2b4b77f8858b3971d832f31cac66433ecfa99f9f1ad7b2c56e75e842429cdb1c",
    ),
];

/// `validator.init_block` from the official mainnet `global.config.json`.
///
/// This is the one block a v0.3.0 client is handed and does not derive. It is not a
/// constant this project invents: it is a field of the config that already decides
/// which network and which servers a client talks to.
const INIT_BLOCK_SEQNO: u32 = 46_894_135;
/// The generation time of that block, used to measure the walk's progress.
const INIT_BLOCK_UTIME: u32 = 1_744_842_508;
const INIT_BLOCK_ROOT_HASH: &str = "3048e69a12cf946ebc99b4cf9ca61c3ff4b3fcc88c4015763ac01204ecc1bf9f";
const INIT_BLOCK_FILE_HASH: &str = "bbdac0b4543e9141449ceb37c3c63ba6e9cc4e2c904d77f56d17e44acf1d1bed";

const QUERY_TIMEOUT: Duration = Duration::from_secs(45);

fn unhex(s: &str) -> [u8; 32] {
    let mut out = [0u8; 32];
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).expect("hex");
    }
    out
}

fn init_block() -> BlockIdExt {
    BlockIdExt {
        workchain: -1,
        shard: MASTERCHAIN_SHARD,
        seqno: INIT_BLOCK_SEQNO,
        root_hash: unhex(INIT_BLOCK_ROOT_HASH),
        file_hash: unhex(INIT_BLOCK_FILE_HASH),
    }
}

/// One liteserver connection, with the query envelope and a timeout around it.
struct Server {
    addr: String,
    connection: AdnlConnection<TcpTransport>,
    sent: usize,
    received: usize,
}

impl Server {
    async fn connect() -> Result<Server, String> {
        let mut last = String::new();
        for (addr, key) in LITESERVERS {
            let attempt = async {
                let transport = TcpTransport::connect(addr)
                    .await
                    .map_err(|e| e.to_string())?;
                AdnlConnection::connect(transport, &unhex(key))
                    .await
                    .map_err(|e| e.to_string())
            };
            match tokio::time::timeout(Duration::from_secs(15), attempt).await {
                Ok(Ok(connection)) => {
                    return Ok(Server {
                        addr: (*addr).to_string(),
                        connection,
                        sent: 0,
                        received: 0,
                    })
                }
                Ok(Err(e)) => last = format!("{addr}: {e}"),
                Err(_) => last = format!("{addr}: timed out"),
            }
            eprintln!("  skipping {last}");
        }
        Err(format!("no liteserver reachable, last was {last}"))
    }

    /// Sends a liteserver method and returns the raw answer bytes.
    async fn query(&mut self, body: Vec<u8>) -> Result<Vec<u8>, String> {
        let envelope = serialize(wire::Query { data: body });
        self.sent += envelope.len();
        let answer = tokio::time::timeout(QUERY_TIMEOUT, self.connection.query(&envelope))
            .await
            .map_err(|_| format!("query timed out after {QUERY_TIMEOUT:?}"))?
            .map_err(|e| e.to_string())?;
        self.received += answer.len();
        Ok(answer)
    }

    async fn head(&mut self) -> Result<BlockIdExt, String> {
        let answer = self.query(GET_MASTERCHAIN_INFO.to_le_bytes().to_vec()).await?;
        let mut r = Reader::new(&answer);
        let id = r.u32().map_err(|e| e.to_string())?;
        if id != MASTERCHAIN_INFO {
            return Err(format!("{id:#010x} is not a masterchainInfo"));
        }
        r.block_id().map_err(|e| e.to_string())
    }

    async fn block_proof(
        &mut self,
        known: &BlockIdExt,
        target: &BlockIdExt,
    ) -> Result<(PartialBlockProof, Vec<u8>), String> {
        let answer = self.query(tl::get_block_proof(known, target)).await?;
        let proof = Reader::partial_block_proof(&answer).map_err(|e| e.to_string())?;
        Ok((proof, answer))
    }
}

#[tokio::main]
async fn main() {
    if let Err(e) = run().await {
        eprintln!("\nSPIKE FAILED: {e}");
        std::process::exit(1);
    }
}

async fn run() -> Result<(), String> {
    println!("== stage 1: can a liteserver prove a chain from the config's init block? ==\n");

    let mut server = Server::connect().await?;
    println!("  connected to {}", server.addr);

    let head = server.head().await?;
    let anchor = init_block();
    println!("  head       {head} seqno {}", head.seqno);
    println!("  init block {anchor} seqno {}", anchor.seqno);
    println!("  distance   {} masterchain blocks", head.seqno - anchor.seqno);

    let started = Instant::now();
    let (proof, raw) = server.block_proof(&anchor, &head).await?;
    let elapsed = started.elapsed();
    let bytes = raw.len();

    println!("\n  the server answered in {elapsed:.1?}, {bytes} bytes");
    println!("  complete: {}", proof.complete);
    println!("  from    : {} seqno {}", proof.from, proof.from.seqno);
    println!("  to      : {} seqno {}", proof.to, proof.to.seqno);
    println!("  steps   : {}", proof.steps.len());

    let mut forward = 0usize;
    let mut back = 0usize;
    let mut signatures = 0usize;
    for step in &proof.steps {
        match step {
            Link::Forward(l) => {
                forward += 1;
                signatures += l.set.signatures().len();
            }
            Link::Back(_) => back += 1,
        }
    }
    println!("  forward : {forward}");
    println!("  backward: {back}");
    if forward > 0 {
        println!("  signatures per forward link: about {}", signatures / forward);
    }

    println!("\n  first few steps:");
    for step in proof.steps.iter().take(5) {
        let (kind, extra) = match step {
            Link::Forward(l) => (
                "forward ",
                format!(
                    "key={} dest_proof={}B config_proof={}B sigs={}",
                    l.to_key_block,
                    l.dest_proof.len(),
                    l.config_proof.len(),
                    l.set.signatures().len()
                ),
            ),
            Link::Back(l) => (
                "backward",
                format!(
                    "key={} dest_proof={}B proof={}B state_proof={}B",
                    l.to_key_block,
                    l.dest_proof.len(),
                    l.proof.len(),
                    l.state_proof.len()
                ),
            ),
        };
        println!(
            "    {kind} {} -> {} ({})",
            step.from().seqno,
            step.to().seqno,
            extra
        );
    }

    let first = proof
        .steps
        .iter()
        .find_map(|step| match step {
            Link::Forward(l) => Some(l),
            Link::Back(_) => None,
        })
        .ok_or_else(|| "no forward link to work from".to_string())?;

    println!("\n== stage 2: the header and the validator set, from the link's own bytes ==\n");

    let header = block::header(&first.dest_proof, &first.to.root_hash)?;
    println!("  destination header for seqno {}", first.to.seqno);
    println!("    key_block                    {}", header.key_block);
    println!("    seq_no                       {}", header.seq_no);
    println!("    gen_utime                    {}", header.gen_utime);
    println!(
        "    gen_catchain_seqno           {}",
        header.gen_catchain_seqno
    );
    println!(
        "    gen_validator_list_hash_short {}",
        header.gen_validator_list_hash_short
    );
    println!(
        "    prev_key_block_seqno         {}",
        header.prev_key_block_seqno
    );
    if header.seq_no != first.to.seqno {
        return Err(format!(
            "the header says seqno {} but the link says {}",
            header.seq_no, first.to.seqno
        ));
    }
    if header.key_block != first.to_key_block {
        return Err("the link's key-block flag disagrees with the header".to_string());
    }

    let set = block::validator_set(&first.config_proof, &first.from.root_hash)?;
    println!("\n  validator set named by key block {}", first.from.seqno);
    println!("    total / main                 {} / {}", set.total, set.main);
    println!(
        "    window                       {} .. {}",
        set.utime_since, set.utime_until
    );
    println!("    masterchain weight           {}", set.total_weight);
    if !(set.utime_since..set.utime_until).contains(&header.gen_utime) {
        println!("    note: the destination's gen_utime is outside this set's window");
    }

    println!("\n== stage 3: which signed form do the signatures cover? ==\n");

    println!("  the set is the {} form\n", first.set.kind());
    report_messages(first, &set);

    let rounds: usize = std::env::args()
        .nth(1)
        .and_then(|a| a.parse().ok())
        .unwrap_or(usize::MAX);
    walk(&mut server, anchor, head, rounds).await
}

/// Stage 4: walk the whole chain, checking every link, and measure what it costs.
async fn walk(
    server: &mut Server,
    from: BlockIdExt,
    head: BlockIdExt,
    max_rounds: usize,
) -> Result<(), String> {
    println!("\n== stage 4: walk the chain to the head, checking every link ==\n");

    let started = Instant::now();
    let mut anchor = from;
    let mut rounds = 0usize;
    let mut links = 0usize;
    let mut signatures = 0usize;
    let mut sets: Vec<u32> = Vec::new();
    let mut thinnest: Option<(f64, u64, u64, u32)> = None;
    let mut network = Duration::ZERO;
    let mut at_utime = 0u32;
    let mut forms: Vec<(&'static str, u32)> = Vec::new();

    loop {
        if rounds >= max_rounds {
            println!("  stopping after {rounds} rounds at the caller's limit");
            break;
        }
        let round_started = Instant::now();
        let (proof, raw) = server.block_proof(&anchor, &head).await?;
        network += round_started.elapsed();
        let bytes = raw.len();
        rounds += 1;

        // One round is the hermetic corpus for the library's link tests: it crosses
        // several rotations and is small enough to check in.
        if rounds == 1 {
            let path = "captured/chain-round-1.tl";
            std::fs::create_dir_all("captured").map_err(|e| e.to_string())?;
            std::fs::write(path, &raw).map_err(|e| e.to_string())?;
            println!("  captured the first reply to {path}");
        }

        if proof.steps.is_empty() {
            return Err(format!("round {rounds} returned no steps, so the walk cannot advance"));
        }
        if proof.from != anchor {
            return Err(format!(
                "round {rounds} starts at {} rather than the block asked about",
                proof.from
            ));
        }

        let before = anchor.seqno;
        for step in &proof.steps {
            if *step.from() != anchor {
                return Err(format!(
                    "a link starts at {} while the chain is at {anchor}",
                    step.from()
                ));
            }
            if step.to().seqno <= anchor.seqno {
                return Err(format!("a link does not move forward, {anchor} to {}", step.to()));
            }
            match step {
                Link::Back(l) => {
                    return Err(format!(
                        "a backward link appeared in an honest chain, {} to {}",
                        l.from, l.to
                    ));
                }
                Link::Forward(l) => {
                    let header = block::header(&l.dest_proof, &l.to.root_hash)?;
                    if header.seq_no != l.to.seqno {
                        return Err("a header disagrees with the link about its seqno".to_string());
                    }
                    if header.key_block != l.to_key_block {
                        return Err("a link's key-block flag disagrees with its header".to_string());
                    }
                    let set = block::validator_set(&l.config_proof, &l.from.root_hash)?;
                    let Some((form, tally)) = candidate_messages(l)
                        .into_iter()
                        .map(|(name, message)| (name, tally(l, &set, &message)))
                        .find(|(_, tally)| tally.carries(set.total_weight))
                    else {
                        println!("\n  no candidate message carries the link to {}:", l.to);
                        report_messages(l, &set);
                        let path = format!("captured/unverified-{}.tl", l.to.seqno);
                        std::fs::write(&path, &raw).map_err(|e| e.to_string())?;
                        return Err(format!(
                            "the {} set on the link to {} verifies under no known message, captured to {path}",
                            l.set.kind(),
                            l.to
                        ));
                    };
                    if forms.last().map(|(f, _)| *f) != Some(form) {
                        println!(
                            "  signatures over {form} from seqno {} ({})",
                            l.to.seqno,
                            l.set.kind()
                        );
                        forms.push((form, l.to.seqno));
                    }
                    let share = tally.share(set.total_weight);
                    if thinnest.is_none_or(|(worst, ..)| share < worst) {
                        thinnest = Some((share, tally.weight, set.total_weight, l.to.seqno));
                    }
                    if sets.last() != Some(&set.utime_since) {
                        sets.push(set.utime_since);
                    }
                    signatures += l.set.signatures().len();
                    at_utime = header.gen_utime;
                }
            }
            anchor = step.to().clone();
            links += 1;
        }

        if anchor.seqno <= before {
            return Err(format!("round {rounds} did not raise the anchor above {before}"));
        }
        println!(
            "  round {rounds:>3}: {:>2} links, {:>7} B, seqno {} ({:.1}% by time)",
            proof.steps.len(),
            bytes,
            anchor.seqno,
            progress(at_utime)
        );

        if proof.complete {
            println!("\n  the server says the chain is complete");
            break;
        }
    }

    let elapsed = started.elapsed();
    println!("\n  reached          {anchor} seqno {}", anchor.seqno);
    println!("  head asked for   seqno {}", head.seqno);
    println!("  rounds           {rounds}");
    println!("  links            {links}");
    println!("  backward links   none, or the walk would have stopped at the first");
    println!("  signatures       {signatures} checked");
    println!("  validator sets   {} distinct, so {} rotations crossed", sets.len(), sets.len().saturating_sub(1));
    println!("  signed forms     {}", forms.iter().map(|(f, s)| format!("{f} from seqno {s}")).collect::<Vec<_>>().join(", "));
    if let Some((share, weight, total, seqno)) = thinnest {
        // The threshold is two thirds, so how far the thinnest real link sits above it
        // is the headroom a stricter signature rule has before it costs liveness.
        println!(
            "  thinnest margin  {:.4}% at seqno {seqno} ({weight} of {total}), {:.4} points above two thirds",
            share * 100.0,
            (share - 2.0 / 3.0) * 100.0
        );
    }
    println!("  received         {:.1} MB", server.received as f64 / 1_048_576.0);
    println!("  elapsed          {elapsed:.1?} ({network:.1?} of it waiting on the network)");
    if links > 0 {
        println!("  per link         {:.1} kB", server.received as f64 / links as f64 / 1024.0);
        println!("  reached utime    {at_utime} ({:.1}% of the way by time)", progress(at_utime));
    }
    Ok(())
}

/// How far along the walk is, measured in time rather than sequence numbers.
///
/// Masterchain block time has changed by nearly an order of magnitude over the span
/// this walk covers, so counting blocks badly misstates progress. Key blocks arrive on
/// a schedule in seconds, so time is the honest measure.
fn progress(at_utime: u32) -> f64 {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as f64)
        .unwrap_or(0.0);
    let span = now - INIT_BLOCK_UTIME as f64;
    if span <= 0.0 || at_utime == 0 {
        0.0
    } else {
        ((at_utime as f64 - INIT_BLOCK_UTIME as f64) / span * 100.0).clamp(0.0, 100.0)
    }
}
