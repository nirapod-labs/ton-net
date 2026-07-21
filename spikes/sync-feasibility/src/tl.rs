//! The block-proof wire types, read by hand.
//!
//! Hand-rolled on purpose. The point of the spike is to pin the layout against real
//! bytes, and a hand reader fails loudly on a wrong guess where a derive might paper
//! over one. What survives here becomes the tl-proto types in step 2.
//!
//! Every constructor id below is CRC32 of the schema line with its parentheses
//! removed, the same rule the ids already in `ton-net-tl` follow. Two are not
//! computed that way and say so.

/// `liteServer.getBlockProof mode:# known_block:tonNode.blockIdExt target_block:mode.0?tonNode.blockIdExt`
pub const GET_BLOCK_PROOF: u32 = 0x8aea_9c44;
/// `liteServer.partialBlockProof complete:Bool from:.. to:.. steps:(vector liteServer.BlockLink)`
pub const PARTIAL_BLOCK_PROOF: u32 = 0x8ed0_d2c1;
/// `liteServer.blockLinkForward`
pub const BLOCK_LINK_FORWARD: u32 = 0x520f_ce1c;
/// `liteServer.blockLinkBack`
pub const BLOCK_LINK_BACK: u32 = 0xef7e_1bef;
/// `liteServer.signatureSet.ordinary#f644a6e6`, an explicit id in the schema.
///
/// It is exactly the id the older bare `liteServer.signatureSet` line computes to, so
/// the union was added without moving the wire form a client already spoke.
pub const SIGNATURE_SET_ORDINARY: u32 = 0xf644_a6e6;
/// `liteServer.signatureSet.simplex`, the second and newer form.
///
/// Its first two integer fields are in the opposite order from the ordinary form, so
/// reading one as the other silently swaps them. This spike refuses it by name.
pub const SIGNATURE_SET_SIMPLEX: u32 = 0xac24_9800;

/// `liteServer.error code:int message:string`
pub const LITE_ERROR: u32 = 0xbba9_e148;

const BOOL_TRUE: u32 = 0x9972_75b5;
const BOOL_FALSE: u32 = 0xbc79_9737;

/// A block identity: the five fields that name one block.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlockIdExt {
    pub workchain: i32,
    pub shard: u64,
    pub seqno: u32,
    pub root_hash: [u8; 32],
    pub file_hash: [u8; 32],
}

impl BlockIdExt {
    /// Writes the bare 80-byte form a request carries.
    pub fn write(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.workchain.to_le_bytes());
        out.extend_from_slice(&self.shard.to_le_bytes());
        out.extend_from_slice(&(self.seqno as i32).to_le_bytes());
        out.extend_from_slice(&self.root_hash);
        out.extend_from_slice(&self.file_hash);
    }
}

impl std::fmt::Display for BlockIdExt {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "({},{:016x},{})", self.workchain, self.shard, self.seqno)
    }
}

/// One validator's signature over a block identity.
#[derive(Debug, Clone)]
pub struct Signature {
    /// The signer's short id: sha256 of the key in its TL `pub.ed25519` form.
    pub node_id_short: [u8; 32],
    pub signature: Vec<u8>,
}

/// What a set of signatures says the validators were voting on.
///
/// Two forms. The original signs the block identity directly. The newer one comes
/// from TON's Simplex consensus and signs a vote naming a candidate, so the block
/// identity is reached through the candidate rather than signed outright.
#[derive(Debug, Clone)]
pub enum SignatureSet {
    Ordinary {
        validator_set_hash: i32,
        catchain_seqno: i32,
        signatures: Vec<Signature>,
    },
    Simplex {
        cc_seqno: i32,
        validator_set_hash: i32,
        signatures: Vec<Signature>,
        session_id: [u8; 32],
        slot: i32,
        /// A serialized `consensus.CandidateHashData`, kept as bytes so it can be
        /// hashed without decoding it.
        candidate: Vec<u8>,
    },
}

impl SignatureSet {
    pub fn signatures(&self) -> &[Signature] {
        match self {
            SignatureSet::Ordinary { signatures, .. }
            | SignatureSet::Simplex { signatures, .. } => signatures,
        }
    }

    pub fn kind(&self) -> &'static str {
        match self {
            SignatureSet::Ordinary { .. } => "ordinary",
            SignatureSet::Simplex { .. } => "simplex",
        }
    }
}

/// A forward step: a key block, and a later block the validators it named signed.
#[derive(Debug, Clone)]
pub struct Forward {
    pub to_key_block: bool,
    pub from: BlockIdExt,
    pub to: BlockIdExt,
    pub dest_proof: Vec<u8>,
    pub config_proof: Vec<u8>,
    pub set: SignatureSet,
}

/// A backward step, which this spike records but does not check.
#[derive(Debug, Clone)]
pub struct Back {
    pub to_key_block: bool,
    pub from: BlockIdExt,
    pub to: BlockIdExt,
    pub dest_proof: Vec<u8>,
    pub proof: Vec<u8>,
    pub state_proof: Vec<u8>,
}

#[derive(Debug, Clone)]
pub enum Link {
    Forward(Forward),
    Back(Back),
}

impl Link {
    pub fn from(&self) -> &BlockIdExt {
        match self {
            Link::Forward(l) => &l.from,
            Link::Back(l) => &l.from,
        }
    }

    pub fn to(&self) -> &BlockIdExt {
        match self {
            Link::Forward(l) => &l.to,
            Link::Back(l) => &l.to,
        }
    }
}

/// The reply: as much of the chain as the server chose to send at once.
#[derive(Debug, Clone)]
pub struct PartialBlockProof {
    pub complete: bool,
    pub from: BlockIdExt,
    pub to: BlockIdExt,
    pub steps: Vec<Link>,
}

/// Builds the `liteServer.getBlockProof` request body.
///
/// Mode bit 0 says a target block follows. Without it the server picks the target,
/// which is not what a client walking to a known head wants.
pub fn get_block_proof(known: &BlockIdExt, target: &BlockIdExt) -> Vec<u8> {
    let mut out = Vec::with_capacity(4 + 4 + 80 + 80);
    out.extend_from_slice(&GET_BLOCK_PROOF.to_le_bytes());
    out.extend_from_slice(&1u32.to_le_bytes());
    known.write(&mut out);
    target.write(&mut out);
    out
}

/// A cursor over TL bytes that refuses to read past the end.
pub struct Reader<'a> {
    bytes: &'a [u8],
    pos: usize,
}

/// What a malformed or unexpected answer looks like.
#[derive(Debug)]
pub struct TlError(pub String);

impl std::fmt::Display for TlError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl std::error::Error for TlError {}

type Result<T> = std::result::Result<T, TlError>;

fn err<T>(msg: impl Into<String>) -> Result<T> {
    Err(TlError(msg.into()))
}

impl<'a> Reader<'a> {
    pub fn new(bytes: &'a [u8]) -> Reader<'a> {
        Reader { bytes, pos: 0 }
    }

    pub fn remaining(&self) -> usize {
        self.bytes.len() - self.pos
    }

    fn take(&mut self, n: usize) -> Result<&'a [u8]> {
        if self.remaining() < n {
            return err(format!(
                "wanted {n} bytes at offset {}, {} left",
                self.pos,
                self.remaining()
            ));
        }
        let out = &self.bytes[self.pos..self.pos + n];
        self.pos += n;
        Ok(out)
    }

    pub fn u32(&mut self) -> Result<u32> {
        Ok(u32::from_le_bytes(self.take(4)?.try_into().unwrap()))
    }

    pub fn i32(&mut self) -> Result<i32> {
        Ok(i32::from_le_bytes(self.take(4)?.try_into().unwrap()))
    }

    pub fn u64(&mut self) -> Result<u64> {
        Ok(u64::from_le_bytes(self.take(8)?.try_into().unwrap()))
    }

    pub fn bytes32(&mut self) -> Result<[u8; 32]> {
        Ok(self.take(32)?.try_into().unwrap())
    }

    /// A TL `Bool`, which is a boxed constructor id rather than the single bit the
    /// cell encoding uses for the same idea.
    pub fn boolean(&mut self) -> Result<bool> {
        match self.u32()? {
            BOOL_TRUE => Ok(true),
            BOOL_FALSE => Ok(false),
            other => err(format!("{other:#010x} is not a Bool")),
        }
    }

    /// A TL `bytes` field: a short or long length, the data, then padding to four.
    pub fn tl_bytes(&mut self) -> Result<Vec<u8>> {
        let first = self.take(1)?[0] as usize;
        let (len, header) = if first < 254 {
            (first, 1)
        } else {
            let more = self.take(3)?;
            (
                more[0] as usize | (more[1] as usize) << 8 | (more[2] as usize) << 16,
                4,
            )
        };
        let data = self.take(len)?.to_vec();
        let padding = (4 - (header + len) % 4) % 4;
        self.take(padding)?;
        Ok(data)
    }

    pub fn block_id(&mut self) -> Result<BlockIdExt> {
        Ok(BlockIdExt {
            workchain: self.i32()?,
            shard: self.u64()?,
            seqno: self.i32()? as u32,
            root_hash: self.bytes32()?,
            file_hash: self.bytes32()?,
        })
    }

    fn signature(&mut self) -> Result<Signature> {
        Ok(Signature {
            node_id_short: self.bytes32()?,
            signature: self.tl_bytes()?,
        })
    }

    fn signatures(&mut self) -> Result<Vec<Signature>> {
        let count = self.u32()? as usize;
        if count > 10_000 {
            return err(format!("{count} signatures in one set"));
        }
        let mut signatures = Vec::with_capacity(count.min(1024));
        for _ in 0..count {
            signatures.push(self.signature()?);
        }
        Ok(signatures)
    }

    fn signature_set(&mut self) -> Result<SignatureSet> {
        match self.u32()? {
            SIGNATURE_SET_ORDINARY => Ok(SignatureSet::Ordinary {
                validator_set_hash: self.i32()?,
                catchain_seqno: self.i32()?,
                signatures: self.signatures()?,
            }),
            // The first two integer fields are in the opposite order from the ordinary
            // form, so reading one as the other silently swaps them.
            SIGNATURE_SET_SIMPLEX => Ok(SignatureSet::Simplex {
                cc_seqno: self.i32()?,
                validator_set_hash: self.i32()?,
                signatures: self.signatures()?,
                session_id: self.bytes32()?,
                slot: self.i32()?,
                candidate: self.tl_bytes()?,
            }),
            other => err(format!("{other:#010x} is not a signature set")),
        }
    }

    fn link(&mut self) -> Result<Link> {
        match self.u32()? {
            BLOCK_LINK_FORWARD => Ok(Link::Forward(Forward {
                to_key_block: self.boolean()?,
                from: self.block_id()?,
                to: self.block_id()?,
                dest_proof: self.tl_bytes()?,
                config_proof: self.tl_bytes()?,
                set: self.signature_set()?,
            })),
            BLOCK_LINK_BACK => Ok(Link::Back(Back {
                to_key_block: self.boolean()?,
                from: self.block_id()?,
                to: self.block_id()?,
                dest_proof: self.tl_bytes()?,
                proof: self.tl_bytes()?,
                state_proof: self.tl_bytes()?,
            })),
            other => err(format!("{other:#010x} is not a block link")),
        }
    }

    /// Reads a whole answer, surfacing a liteserver error as one.
    pub fn partial_block_proof(bytes: &[u8]) -> Result<PartialBlockProof> {
        let mut r = Reader::new(bytes);
        let id = r.u32()?;
        if id == LITE_ERROR {
            let code = r.i32()?;
            let message = String::from_utf8_lossy(&r.tl_bytes()?).into_owned();
            return err(format!("liteserver error {code}: {message}"));
        }
        if id != PARTIAL_BLOCK_PROOF {
            return err(format!("{id:#010x} is not a partialBlockProof"));
        }
        let complete = r.boolean()?;
        let from = r.block_id()?;
        let to = r.block_id()?;
        let count = r.u32()? as usize;
        if count > 10_000 {
            return err(format!("{count} steps in one reply"));
        }
        let mut steps = Vec::with_capacity(count.min(1024));
        for _ in 0..count {
            steps.push(r.link()?);
        }
        // A reply with bytes left over means the layout above is wrong somewhere, which
        // is worth failing on in a spike whose job is to pin the layout.
        if r.remaining() != 0 {
            return err(format!("{} bytes left after the reply", r.remaining()));
        }
        Ok(PartialBlockProof {
            complete,
            from,
            to,
            steps,
        })
    }
}
