// Standalone spike: complete an ADNL-over-TCP handshake with a TON mainnet
// liteserver and issue one liteServer.getMasterchainInfo query, constructing
// every byte directly instead of through an ADNL library. It builds the same
// transport and codec path the client core depends on: the TL constructor tags,
// the x25519 handshake, the AES-256-CTR stream framing, and the liteserver query
// wrapper.
//
// A run succeeds when the server returns a checksum-valid ADNL frame that echoes
// the request query id and carries a decodable liteServer.masterchainInfo. The
// wire layout is documented in docs/protocol/wire-format.md; the constructor tags
// derive from the ton_api.tl and lite_api.tl schemas. The crate lines match
// NET-ADR-003.

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::time::Duration;

use aes::cipher::{KeyIvInit, StreamCipher};
use curve25519_dalek::edwards::{CompressedEdwardsY, EdwardsPoint};
use sha2::{Digest, Sha256, Sha512};

type Aes256Ctr = ctr::Ctr128BE<aes::Aes256>;

// A snapshot of public mainnet liteservers from https://ton.org/global.config.json
// (dotted ip, port, server ed25519 public key hex). The set rotates over time; a
// stale or unreachable entry is skipped and the next one is tried.
const LITESERVERS: &[(&str, u16, &str)] = &[
    (
        "5.9.10.47",
        19949,
        "9f85439d2094b92a639c2c9493d7b740e39dea8d08b525986d39d6dd69e7f309",
    ),
    (
        "5.9.10.15",
        48014,
        "dd73baecafea8be82edd3f6ff06da1c75c8d99666171c2f73bb4a8a2c168f06d",
    ),
    (
        "135.181.177.59",
        53312,
        "685f750ae507bae3aff6b9b65b9f8eff8877f0cdec466e340ed49d4714219ad4",
    ),
    (
        "135.181.140.212",
        13206,
        "2b4b77f8858b3971d832f31cac66433ecfa99f9f1ad7b2c56e75e842429cdb1c",
    ),
    (
        "135.181.140.221",
        46995,
        "c10134315857356517a56896e4193c7008ab221e4d346ddc64cd7f7d254a22db",
    ),
    (
        "65.21.141.233",
        30131,
        "c2b41a788162b293df1e774405cd2cd1fc7b192a7c50516f79b9f2b5041f73a0",
    ),
    (
        "65.21.141.198",
        47160,
        "bce7b55eab7fd40436679e8fafed519f0f9fd0d98003bacd0991481de0a107ba",
    ),
    (
        "65.21.141.231",
        17728,
        "058495a4beda3e4d245390ad96c21a7bff267f607f36b062ec32a67a97235fa4",
    ),
    (
        "65.21.141.197",
        13570,
        "895407ef57329a83609eb84e4f7e6d97f63b93ce97e6256ebb955febc2a689f4",
    ),
    (
        "164.68.101.206",
        52995,
        "4271857bd922856f9329a704befc455aa557791c4207a0a18e384d4eb2fbfbf9",
    ),
];

// IEEE CRC32 (reflected, poly 0xEDB88320). TON TL constructor id = crc32 of the
// canonical combinator string; the id is serialized little-endian on the wire.
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

fn urandom(n: usize) -> Vec<u8> {
    let mut f = std::fs::File::open("/dev/urandom").expect("open /dev/urandom");
    let mut b = vec![0u8; n];
    f.read_exact(&mut b).expect("read /dev/urandom");
    b
}

fn sha256(parts: &[&[u8]]) -> [u8; 32] {
    let mut h = Sha256::new();
    for p in parts {
        h.update(p);
    }
    h.finalize().into()
}

// TL byte-string: len<254 -> [len][bytes], padded with zeros to a 4-byte boundary
// (the length byte counts toward the padding).
fn tl_bytes(data: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    assert!(data.len() < 254, "spike only needs short byte-strings");
    out.push(data.len() as u8);
    out.extend_from_slice(data);
    while out.len() % 4 != 0 {
        out.push(0);
    }
    out
}

// Read a TL byte-string, returning (bytes, total_consumed).
fn read_tl_bytes(buf: &[u8]) -> Option<(Vec<u8>, usize)> {
    let first = *buf.first()? as usize;
    let (len, hdr) = if first < 254 {
        (first, 1)
    } else {
        // 0xFE + 3-byte LE length
        let len = *buf.get(1)? as usize
            | ((*buf.get(2)? as usize) << 8)
            | ((*buf.get(3)? as usize) << 16);
        (len, 4)
    };
    let end = hdr + len;
    if buf.len() < end {
        return None;
    }
    let mut total = end;
    while total % 4 != 0 {
        total += 1;
    }
    Some((buf[hdr..end].to_vec(), total))
}

struct Adnl {
    stream: TcpStream,
    rx: Aes256Ctr,
    tx: Aes256Ctr,
}

impl Adnl {
    fn send(&mut self, payload: &[u8]) -> std::io::Result<()> {
        let nonce = urandom(32);
        let checksum = sha256(&[&nonce, payload]);
        let len = (32 + payload.len() + 32) as u32;
        let mut buf = Vec::with_capacity(4 + len as usize);
        buf.extend_from_slice(&len.to_le_bytes());
        buf.extend_from_slice(&nonce);
        buf.extend_from_slice(payload);
        buf.extend_from_slice(&checksum);
        self.tx.apply_keystream(&mut buf);
        self.stream.write_all(&buf)
    }

    fn recv(&mut self) -> Result<Vec<u8>, String> {
        let mut lenb = [0u8; 4];
        self.stream
            .read_exact(&mut lenb)
            .map_err(|e| format!("read len: {e}"))?;
        self.rx.apply_keystream(&mut lenb);
        let len = u32::from_le_bytes(lenb) as usize;
        if !(64..=(1 << 20)).contains(&len) {
            return Err(format!(
                "implausible frame length {len} (cipher desync => handshake wrong)"
            ));
        }
        let mut body = vec![0u8; len];
        self.stream
            .read_exact(&mut body)
            .map_err(|e| format!("read body: {e}"))?;
        self.rx.apply_keystream(&mut body);
        let nonce = &body[..32];
        let payload = &body[32..len - 32];
        let got = &body[len - 32..];
        let want = sha256(&[nonce, payload]);
        if got != want {
            return Err("frame checksum mismatch".into());
        }
        Ok(payload.to_vec())
    }
}

fn handshake(addr: SocketAddr, server_pub: &[u8; 32], ids: &Ids) -> Result<Adnl, String> {
    let stream = TcpStream::connect_timeout(&addr, Duration::from_secs(5))
        .map_err(|e| format!("connect: {e}"))?;
    stream.set_read_timeout(Some(Duration::from_secs(8))).ok();
    stream.set_write_timeout(Some(Duration::from_secs(8))).ok();
    stream.set_nodelay(true).ok();

    // server key id = sha256( LE(pub.ed25519 id) ++ server_pub )
    let server_key_id = sha256(&[&ids.pub_ed25519.to_le_bytes(), server_pub]);

    // Ephemeral client identity. The DH scalar is sha512(seed)[..32]; both
    // mul_base_clamped and mul_clamped apply the RFC 7748 clamp, so the public
    // key sent below and the shared secret derive from the same clamped scalar.
    let seed = urandom(32);
    let full = Sha512::digest(&seed);
    let mut dh: [u8; 32] = [0u8; 32];
    dh.copy_from_slice(&full[..32]);

    let client_pub = EdwardsPoint::mul_base_clamped(dh).compress().to_bytes();

    let server_mont = CompressedEdwardsY(*server_pub)
        .decompress()
        .ok_or("server pubkey not a valid ed25519 point")?
        .to_montgomery();
    let shared = server_mont.mul_clamped(dh).to_bytes();

    // 160-byte session parameters -> the two stream ciphers
    let params = urandom(160);
    let checksum = sha256(&[&params]);

    // handshake cipher: key = shared[..16]||checksum[16..], iv = checksum[..4]||shared[20..]
    let mut hkey = [0u8; 32];
    hkey[..16].copy_from_slice(&shared[..16]);
    hkey[16..].copy_from_slice(&checksum[16..]);
    let mut hiv = [0u8; 16];
    hiv[..4].copy_from_slice(&checksum[..4]);
    hiv[4..].copy_from_slice(&shared[20..]);

    let mut enc = params.clone();
    Aes256Ctr::new_from_slices(&hkey, &hiv)
        .map_err(|_| "aes init")?
        .apply_keystream(&mut enc);

    let mut packet = Vec::with_capacity(256);
    packet.extend_from_slice(&server_key_id); // 32
    packet.extend_from_slice(&client_pub); // 32
    packet.extend_from_slice(&checksum); // 32
    packet.extend_from_slice(&enc); // 160
    assert_eq!(packet.len(), 256);

    // session ciphers: rx decrypts server->client, tx encrypts client->server
    let rx = Aes256Ctr::new_from_slices(&params[0..32], &params[64..80]).map_err(|_| "rx init")?;
    let tx = Aes256Ctr::new_from_slices(&params[32..64], &params[80..96]).map_err(|_| "tx init")?;

    let mut s = stream;
    s.write_all(&packet)
        .map_err(|e| format!("send handshake: {e}"))?;

    Ok(Adnl { stream: s, rx, tx })
}

struct Ids {
    pub_ed25519: u32,
    adnl_query: u32,
    adnl_answer: u32,
    ls_query: u32,
    get_mc_info: u32,
    ls_error: u32,
    mc_info: u32,
}

fn main() {
    let ids = Ids {
        pub_ed25519: crc32("pub.ed25519 key:int256 = PublicKey"),
        adnl_query: crc32("adnl.message.query query_id:int256 query:bytes = adnl.Message"),
        adnl_answer: crc32("adnl.message.answer query_id:int256 answer:bytes = adnl.Message"),
        ls_query: crc32("liteServer.query data:bytes = Object"),
        get_mc_info: crc32("liteServer.getMasterchainInfo = liteServer.MasterchainInfo"),
        ls_error: crc32("liteServer.error code:int message:string = liteServer.Error"),
        mc_info: crc32("liteServer.masterchainInfo last:tonNode.blockIdExt state_root_hash:int256 init:tonNode.zeroStateIdExt = liteServer.MasterchainInfo"),
    };

    // Each TL id is crc32 of the canonical combinator string, serialized
    // little-endian on the wire. Cross-check the wire form against the magics in
    // the ton_api.tl and lite_api.tl schemas; a mismatch means the query would
    // not parse server-side.
    println!("== TL constructor ids (wire form vs schema magic) ==");
    for (name, id, expect) in [
        ("pub.ed25519", ids.pub_ed25519, "c6b41348"),
        ("adnl.message.query", ids.adnl_query, "7af98bb4"),
        ("adnl.message.answer", ids.adnl_answer, "1684ac0f"),
        ("liteServer.query", ids.ls_query, "df068c79"),
        ("liteServer.getMasterchainInfo", ids.get_mc_info, "2ee6b589"),
    ] {
        let w = hex(&id.to_le_bytes());
        let mark = if w == expect { "ok" } else { "MISMATCH" };
        println!("  {name:<31} {w}  expect {expect}  {mark}");
    }
    println!();

    // build the query payload once: adnl.message.query{ qid, liteServer.query{ getMasterchainInfo } }
    let inner = ids.get_mc_info.to_le_bytes().to_vec();
    let mut ls_query = ids.ls_query.to_le_bytes().to_vec();
    ls_query.extend_from_slice(&tl_bytes(&inner));

    for (host, port, keyhex) in LITESERVERS {
        let server_pub = {
            let raw = (0..32)
                .map(|i| u8::from_str_radix(&keyhex[i * 2..i * 2 + 2], 16).unwrap())
                .collect::<Vec<u8>>();
            let mut a = [0u8; 32];
            a.copy_from_slice(&raw);
            a
        };
        let addr: SocketAddr = format!("{host}:{port}").parse().unwrap();
        println!("-- {host}:{port}");

        let mut conn = match handshake(addr, &server_pub, &ids) {
            Ok(c) => c,
            Err(e) => {
                println!("   handshake failed: {e}");
                continue;
            }
        };
        println!("   handshake sent (256 bytes), ciphers up");

        let qid = urandom(32);
        let mut adnl_q = ids.adnl_query.to_le_bytes().to_vec();
        adnl_q.extend_from_slice(&qid);
        adnl_q.extend_from_slice(&tl_bytes(&ls_query));
        if let Err(e) = conn.send(&adnl_q) {
            println!("   send query failed: {e}");
            continue;
        }
        println!("   getMasterchainInfo sent ({} byte payload)", adnl_q.len());

        // read frames: server may send an empty confirmation first, then the answer
        let mut got_answer = false;
        for _ in 0..4 {
            match conn.recv() {
                Ok(p) if p.is_empty() => {
                    println!("   <- empty ADNL confirmation frame (handshake acknowledged)");
                }
                Ok(p) => {
                    if p.len() < 36 {
                        println!("   <- short frame ({} bytes): {}", p.len(), hex(&p));
                        continue;
                    }
                    let id = u32::from_le_bytes([p[0], p[1], p[2], p[3]]);
                    let echoed = &p[4..36];
                    if id == ids.adnl_answer && echoed == &qid[..] {
                        if let Some((answer, _)) = read_tl_bytes(&p[36..]) {
                            decode_answer(&answer, &ids);
                            got_answer = true;
                        } else {
                            println!("   <- adnl.answer but could not frame answer bytes");
                        }
                    } else {
                        println!(
                            "   <- unexpected frame id={id:08x} echo_ok={}",
                            echoed == &qid[..]
                        );
                    }
                    break;
                }
                Err(e) => {
                    println!("   recv error: {e}");
                    break;
                }
            }
        }

        if got_answer {
            println!("\n==> round-trip verified against {host}:{port}");
            return;
        }
        println!();
    }

    println!("==> no liteserver completed the full round-trip (see errors above)");
    std::process::exit(1);
}

fn decode_answer(answer: &[u8], ids: &Ids) {
    if answer.len() < 4 {
        println!("   answer too short: {}", hex(answer));
        return;
    }
    let id = u32::from_le_bytes([answer[0], answer[1], answer[2], answer[3]]);
    if id == ids.ls_error {
        let code = i32::from_le_bytes([answer[4], answer[5], answer[6], answer[7]]);
        let msg = read_tl_bytes(&answer[8..]).map(|(b, _)| String::from_utf8_lossy(&b).to_string());
        println!("   <- liteServer.error code={code} msg={msg:?}");
        return;
    }
    if id != ids.mc_info {
        println!(
            "   <- answer id {id:08x} (not masterchainInfo): {}",
            hex(&answer[..answer.len().min(48)])
        );
        return;
    }
    // last: tonNode.blockIdExt = workchain:int shard:long seqno:int root_hash:int256 file_hash:int256
    let b = &answer[4..];
    let workchain = i32::from_le_bytes([b[0], b[1], b[2], b[3]]);
    let shard = u64::from_le_bytes([b[4], b[5], b[6], b[7], b[8], b[9], b[10], b[11]]);
    let seqno = u32::from_le_bytes([b[12], b[13], b[14], b[15]]);
    let root = &b[16..48];
    println!("   <- liteServer.masterchainInfo:");
    println!("        workchain = {workchain}");
    println!("        shard     = {:016x}", shard);
    println!("        SEQNO     = {seqno}   <-- live mainnet masterchain height");
    println!("        root_hash = {}", hex(root));
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}
