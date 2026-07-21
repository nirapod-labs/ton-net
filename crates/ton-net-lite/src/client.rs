//! The liteserver read client and its query and decode helpers.

use ton_net_adnl::{AdnlConnection, Transport};
use ton_net_tl::lite as wire;
use ton_net_tl::{deserialize, serialize, TlRead, TlWrite};

use crate::types::{AccountState, BlockIdExt, MasterchainInfo, ServerReported};

/// A read client for one liteserver.
///
/// A `LiteClient` owns one ADNL connection and issues liteserver read queries over it,
/// one at a time. It is built from a connected [`AdnlConnection`] with [`new`](Self::new)
/// or opened directly with [`connect`](Self::connect). Reads are returned as
/// [`ServerReported`] values and are not proof-verified in this release.
pub struct LiteClient<T> {
    connection: AdnlConnection<T>,
}

/// A failure reading from a liteserver.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum LiteError {
    /// The ADNL layer failed: a transport, framing, or handshake error.
    #[error(transparent)]
    Adnl(#[from] ton_net_adnl::AdnlError),

    /// The liteserver returned an error in place of a result.
    #[error("liteserver error {code}: {message}")]
    LiteServer {
        /// The liteserver error code.
        code: i32,
        /// The human-readable error message.
        message: String,
    },

    /// The answer bytes did not decode as the expected response.
    #[error("could not decode the liteserver answer")]
    Decode(#[from] ton_net_tl::TlError),
}

impl<T: Transport> LiteClient<T> {
    /// Wraps an already connected [`AdnlConnection`] as a read client.
    pub fn new(connection: AdnlConnection<T>) -> Self {
        Self { connection }
    }

    /// Opens a connection over `transport` and completes the ADNL handshake.
    ///
    /// # Errors
    ///
    /// Returns [`LiteError::Adnl`] if the handshake cannot be sent or the server key is
    /// not a valid point.
    pub async fn connect(transport: T, server_key: &[u8; 32]) -> Result<Self, LiteError> {
        Ok(Self::new(
            AdnlConnection::connect(transport, server_key).await?,
        ))
    }

    /// Reads the liteserver's current masterchain head.
    ///
    /// The masterchain info carries no proof, so the returned wrapper's proof is empty.
    ///
    /// # Errors
    ///
    /// Returns [`LiteError::LiteServer`] if the server returns an error, [`LiteError::Decode`]
    /// if the answer does not decode, or [`LiteError::Adnl`] on a transport or framing
    /// failure.
    pub async fn masterchain_info(&mut self) -> Result<ServerReported<MasterchainInfo>, LiteError> {
        let answer = self
            .connection
            .query(&build_query(wire::GetMasterchainInfo))
            .await?;
        let info: wire::MasterchainInfo = decode_answer(&answer)?;
        Ok(ServerReported::new(
            MasterchainInfo {
                last: block_id(info.last),
                state_root_hash: info.state_root_hash,
            },
            Vec::new(),
        ))
    }

    /// Reads an account's raw state at a given masterchain block.
    ///
    /// `block` is usually the head from [`masterchain_info`](Self::masterchain_info).
    /// The account-state proof the server sends is kept on the returned wrapper, and the
    /// shard proof that links the account's shard block to `block` is kept on the state.
    /// Neither is checked here.
    ///
    /// # Errors
    ///
    /// Returns [`LiteError::LiteServer`] if the server returns an error, [`LiteError::Decode`]
    /// if the answer does not decode, or [`LiteError::Adnl`] on a transport or framing
    /// failure.
    pub async fn account_state(
        &mut self,
        block: &BlockIdExt,
        account: &wire::AccountId,
    ) -> Result<ServerReported<AccountState>, LiteError> {
        let request = wire::GetAccountState {
            id: wire_block(block),
            account: account.clone(),
        };
        let answer = self.connection.query(&build_query(request)).await?;
        let state: wire::AccountState = decode_answer(&answer)?;
        Ok(ServerReported::new(
            AccountState {
                block: block_id(state.id),
                shard_block: block_id(state.shardblk),
                shard_proof: state.shard_proof,
                state: state.state,
            },
            state.proof,
        ))
    }
}

/// Wraps a liteserver request in a `liteServer.query` envelope, ready to be an ADNL
/// query payload.
fn build_query<R: TlWrite>(request: R) -> Vec<u8> {
    serialize(wire::Query {
        data: serialize(request),
    })
}

/// Decodes an ADNL answer as `R`, or as a liteserver error if that is what it is.
///
/// The answer is one of two things: the expected response, or a `liteServer.error`. The
/// two carry distinct constructor ids, so a successful error decode means the server
/// returned an error and it is surfaced as [`LiteError::LiteServer`]; anything else is
/// decoded as `R`.
fn decode_answer<R>(answer: &[u8]) -> Result<R, LiteError>
where
    R: for<'a> TlRead<'a>,
{
    if let Ok(error) = deserialize::<wire::Error>(answer) {
        return Err(LiteError::LiteServer {
            code: error.code,
            message: String::from_utf8_lossy(&error.message).into_owned(),
        });
    }
    Ok(deserialize::<R>(answer)?)
}

/// Maps a wire block id to the domain form; the sequence number is a height and becomes
/// unsigned.
fn block_id(wire: wire::BlockIdExt) -> BlockIdExt {
    BlockIdExt {
        workchain: wire.workchain,
        shard: wire.shard,
        seqno: wire.seqno as u32,
        root_hash: wire.root_hash,
        file_hash: wire.file_hash,
    }
}

/// Maps a domain block id back to the wire form for a request.
fn wire_block(block: &BlockIdExt) -> wire::BlockIdExt {
    wire::BlockIdExt {
        workchain: block.workchain,
        shard: block.shard,
        seqno: block.seqno as i32,
        root_hash: block.root_hash,
        file_hash: block.file_hash,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    fn unhex(s: &str) -> Vec<u8> {
        (0..s.len() / 2)
            .map(|i| u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).unwrap())
            .collect()
    }

    // The same real mainnet liteServer.masterchainInfo the tl crate anchors its decode
    // to (captured at seqno 80945431), reused here to test the decode path.
    const MAINNET_MASTERCHAIN_INFO: &str = "81288385ffffffff00000000000000801721d3045fab3692062c45ef57802846943439f41ab442198c48e9c846274fa703e9efe8f1e0421cee64950897a206aa3f377355edc7bb96bb578f7a7381bf3ee7fb70e58455b4866a10724ac7d855dfbe2d73e4fab7a89a15a2c534dea37c87fa3a28aeffffffff17a3a92992aabea785a7a090985a265cd31f323d849da51239737e321fb055695e994fcf4d425c0a6ce6a792594b7173205f740a39cd56f537defd28b48a0f6e";

    #[test]
    fn build_query_wraps_the_request_as_a_liteserver_query() {
        // liteServer.query id, then getMasterchainInfo as a 4-byte bytes field padded to
        // the 4-byte boundary. This is the payload the tl crate's spike vector wraps.
        assert_eq!(
            hex(&build_query(wire::GetMasterchainInfo)),
            "df068c79042ee6b589000000"
        );
    }

    #[test]
    fn decode_answer_decodes_a_real_masterchain_info() {
        let bytes = unhex(MAINNET_MASTERCHAIN_INFO);
        let info: wire::MasterchainInfo = decode_answer(&bytes).unwrap();
        assert_eq!(info.last.workchain, -1);
        assert_eq!(info.last.seqno, 80_945_431);
    }

    #[test]
    fn decode_answer_surfaces_a_liteserver_error() {
        let bytes = serialize(wire::Error {
            code: -400,
            message: b"bad request".to_vec(),
        });
        let result: Result<wire::MasterchainInfo, _> = decode_answer(&bytes);
        assert!(matches!(
            result,
            Err(LiteError::LiteServer { code: -400, ref message }) if message == "bad request"
        ));
    }

    #[test]
    fn decode_answer_rejects_bytes_that_are_neither() {
        let result: Result<wire::MasterchainInfo, _> = decode_answer(&[0xde, 0xad, 0xbe, 0xef]);
        assert!(matches!(result, Err(LiteError::Decode(_))));
    }

    #[test]
    fn block_id_maps_wire_to_domain() {
        let wire = wire::BlockIdExt {
            workchain: -1,
            shard: 0x8000_0000_0000_0000,
            seqno: 42,
            root_hash: [1; 32],
            file_hash: [2; 32],
        };
        let domain = block_id(wire);
        assert_eq!(domain.workchain, -1);
        assert_eq!(domain.shard, 0x8000_0000_0000_0000);
        assert_eq!(domain.seqno, 42_u32);
    }
}
