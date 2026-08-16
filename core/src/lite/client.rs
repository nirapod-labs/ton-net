// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Nirapod Labs

//! The liteserver read client and its query and decode helpers.

use crate::adnl::{AdnlConnection, Transport};
use crate::tl::lite as wire;
use crate::tl::{deserialize, serialize, TlRead, TlWrite};

use crate::lite::types::{Accepted, AccountState, BlockIdExt, MasterchainInfo, ServerReported};

/// The phrase a server writes when it refuses a send it has already been given.
///
/// The reference node raises that refusal with no error code of its own, so the code it
/// arrives under is the same zero every other uncoded error on this path carries and
/// tells the two apart from nothing. The text is the only part that distinguishes it,
/// and it is matched as a substring because the node prefixes the phrase with a sentence
/// naming the operation before it reaches the wire.
const DUPLICATE_SEND: &str = "duplicate message";

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
    Adnl(#[from] crate::adnl::AdnlError),

    /// The liteserver returned an error in place of a result.
    #[error("liteserver error {code}: {message}")]
    LiteServer {
        /// The liteserver error code.
        code: i32,
        /// The human-readable error message.
        message: String,
    },

    /// The server refused a send because it had already been given the same request.
    ///
    /// Kept apart from [`LiteServer`](Self::LiteServer) because it reads like a failure
    /// and is not one: see [`send_message`](LiteClient::send_message) for what it does
    /// and does not establish about the earlier offer.
    ///
    /// **The scope of the recognition is one implementation's wording.** A server that
    /// phrases the refusal differently arrives as [`LiteServer`](Self::LiteServer)
    /// instead, which is where every refusal arrived before this variant existed, so
    /// the cost of missing one is the behaviour that already stood.
    #[error("the liteserver had already taken this request: {message}")]
    DuplicateSend {
        /// The error code the server sent, carried unchanged. It did not take part in
        /// recognizing the error and is kept so that nothing downstream has to invent
        /// one for an error the server did put a code on.
        code: i32,
        /// The message the server sent, kept verbatim rather than replaced, because the
        /// wording is the only evidence there is that this is what it is.
        message: String,
    },

    /// The answer bytes did not decode as the expected response.
    #[error("could not decode the liteserver answer")]
    Decode(#[from] crate::tl::TlError),
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
                last: info.last.into(),
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
            id: block.into(),
            account: account.clone(),
        };
        let answer = self.connection.query(&build_query(request)).await?;
        let state: wire::AccountState = decode_answer(&answer)?;
        Ok(ServerReported::new(
            AccountState {
                block: state.id.into(),
                shard_block: state.shardblk.into(),
                shard_proof: state.shard_proof,
                state: state.state,
            },
            state.proof,
        ))
    }

    /// Offers an external message to the network through this server.
    ///
    /// `boc` is a finished external message, serialized as a bag of cells. Nothing here
    /// builds one, reads one, or checks that the bytes are a message at all: this layer
    /// cannot name a cell, so what it hands over is whatever the caller composed. The
    /// answer is an [`Accepted`], whose documentation is where the meaning of a
    /// successful send is written out, and it is deliberately not a read.
    ///
    /// **One error on this path means the opposite of what it reads as.** A server
    /// refuses a request it has already been given, and the refusal arrives as an
    /// ordinary liteserver error. Reading it as a failure is the expensive mistake
    /// available here, because a caller whose own retry produced it would report a
    /// failure for a message that had already been taken. It comes back as
    /// [`LiteError::DuplicateSend`] instead, so the judgement is made once, here, rather
    /// than by a text comparison at each call site.
    ///
    /// **What that refusal establishes, at its exact scope.** These are external facts
    /// about liteserver behaviour rather than anything this tree checks. On this path the
    /// server deduplicates on a hash of the whole serialized request, not the message
    /// inside it, because the same node keys its broadcast path on the message bytes
    /// instead. So it is these exact bytes that are compared, and the comparison covers
    /// a bounded recent
    /// window rather than all of history. Within that window an identical request reached
    /// this server and the server did not refuse it. That is
    /// less than saying the earlier offer succeeded: an entry is recorded before the
    /// message is run and removed again if the run fails, so a second request arriving
    /// while the first is still being run is refused as a duplicate too. Nothing about
    /// inclusion follows from it either, for the reason [`Accepted`] gives.
    ///
    /// # Errors
    ///
    /// Returns [`LiteError::DuplicateSend`] if the server recognized the request as one
    /// it had already taken, [`LiteError::LiteServer`] for any other error the server
    /// returns, [`LiteError::Decode`] if the answer does not decode, or
    /// [`LiteError::Adnl`] on a transport or framing failure.
    pub async fn send_message(&mut self, boc: &[u8]) -> Result<Accepted, LiteError> {
        let request = wire::SendMessage { body: boc.to_vec() };
        let answer = self.connection.query(&build_query(request)).await?;
        let status: wire::SendMsgStatus = decode_answer(&answer).map_err(name_a_duplicate)?;
        Ok(Accepted::new(status.status))
    }

    /// Asks the server to prove a chain from a block the caller trusts to a later one.
    ///
    /// The answer is a run of links, each one a step the caller has to check. It comes
    /// back as the wire type rather than a domain twin: unlike a read, nothing here is
    /// a value to be consumed, and every field is evidence for a verifier to weigh.
    /// Re-shaping it would mean two definitions of the same bytes and no reader served
    /// by either.
    ///
    /// The server chooses the route, and may stop short of `target`; when it does,
    /// [`complete`](wire::PartialBlockProof::complete) is false and the caller asks
    /// again from where the answer ended. **None of it is checked here.** A run of
    /// links that connects nothing, or ends somewhere else entirely, is a well-formed
    /// answer to this call.
    ///
    /// # Errors
    ///
    /// Returns [`LiteError::LiteServer`] if the server returns an error, [`LiteError::Decode`]
    /// if the answer does not decode, or [`LiteError::Adnl`] on a transport or framing
    /// failure.
    pub async fn block_proof(
        &mut self,
        known: &BlockIdExt,
        target: &BlockIdExt,
    ) -> Result<wire::PartialBlockProof, LiteError> {
        // The request can leave the target out and let the server pick one, which is
        // not offered: a client walking towards a head it has already chosen gains
        // nothing from letting the server choose for it.
        let request = wire::GetBlockProof {
            mode: (),
            known_block: known.into(),
            target_block: Some(target.into()),
        };
        let answer = self.connection.query(&build_query(request)).await?;
        decode_answer(&answer)
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

/// Renames a server error that is a duplicate refusal, and leaves every other error be.
///
/// It is applied on the send path alone rather than inside [`decode_answer`], because
/// the refusal is raised by one request and a reading that covered the others would be
/// wider than the fact under it.
fn name_a_duplicate(error: LiteError) -> LiteError {
    match error {
        LiteError::LiteServer { code, message } if message.contains(DUPLICATE_SEND) => {
            LiteError::DuplicateSend { code, message }
        }
        other => other,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(bytes: &[u8]) -> String {
        use std::fmt::Write as _;

        bytes.iter().fold(String::new(), |mut hex, b| {
            let _ = write!(hex, "{b:02x}");
            hex
        })
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
    fn build_query_lays_out_a_block_proof_request_the_way_mainnet_took_it() {
        let block = BlockIdExt {
            workchain: -1,
            shard: 0x8000_0000_0000_0000,
            seqno: 46_894_135,
            root_hash: [0x11; 32],
            file_hash: [0x22; 32],
        };
        let body = serialize(wire::GetBlockProof {
            mode: (),
            known_block: (&block).into(),
            target_block: Some((&block).into()),
        });

        // Constructor id, then the mode word with bit 0 set for the target that
        // follows, then two 80-byte block ids. This is the layout the feasibility
        // spike built by hand and a mainnet liteserver answered.
        assert_eq!(&body[..4], [0x44, 0x9c, 0xea, 0x8a]);
        assert_eq!(&body[4..8], [1, 0, 0, 0]);
        assert_eq!(body.len(), 4 + 4 + 80 + 80);
        assert_eq!(&body[8..88], &body[88..]);

        // The envelope is the same one every other request travels in.
        let query = build_query(wire::GetBlockProof {
            mode: (),
            known_block: (&block).into(),
            target_block: Some((&block).into()),
        });
        assert_eq!(&hex(&query[..4]), "df068c79");
    }

    // A real mainnet exchange, captured against the liteserver `mainnet_lite.rs` dials.
    // The body offered is four bytes that are not a bag of cells, so the server took the
    // request, failed to read a message out of the body, and refused; nothing was
    // broadcast and no value moved. What the pair pins is the half a scheme reading
    // cannot. A constructor id computed from a scheme line is a hypothesis about what a
    // server will call these bytes, and a refusal that names the *body* is what settles
    // it, because a request under an id the server does not know is refused before any
    // body is looked at and answers something else.
    const MAINNET_SEND_REQUEST: &str = "82d40a6904deadbeef000000";
    const MAINNET_SEND_ANSWER: &str = "48e1a9bb000000006963616e6e6f74206170706c792065787465726e616c206d65737361676520746f2063757272656e74207374617465203a2063616e6e6f7420646573657269616c697a65206261672d6f662d63656c6c733a20696e76616c6964206865616465722c206572726f7220300000";
    const MAINNET_SEND_REFUSAL: &str =
        "cannot apply external message to current state : cannot deserialize bag-of-cells: invalid header, error 0";

    #[test]
    fn send_message_wire_lays_out_the_request_the_way_mainnet_took_it() {
        let body = serialize(wire::SendMessage {
            body: vec![0xde, 0xad, 0xbe, 0xef],
        });

        // Constructor id, then the body as a TL bytes field: one length byte, the four
        // bytes, then three of padding to the next four-byte boundary.
        assert_eq!(hex(&body), MAINNET_SEND_REQUEST);
        assert_eq!(&body[..4], [0x82, 0xd4, 0x0a, 0x69]);
        assert_eq!(body.len(), 4 + 1 + 4 + 3);

        // The envelope is the same one every other request travels in.
        let query = build_query(wire::SendMessage {
            body: vec![0xde, 0xad, 0xbe, 0xef],
        });
        // Query id, then one length byte for a twelve-byte payload, then the request
        // itself and three bytes of padding.
        assert_eq!(&hex(&query[..4]), "df068c79");
        assert_eq!(query[4], 12);
        assert_eq!(hex(&query[5..5 + body.len()]), MAINNET_SEND_REQUEST);
    }

    #[test]
    fn send_message_wire_reads_the_answer_mainnet_gave_that_request() {
        // The server refused the body rather than the request, which is what shows it
        // understood the request. A wrong constructor id is refused before any body is
        // looked at and answers something else entirely.
        let answer = unhex(MAINNET_SEND_ANSWER);
        let result: Result<wire::SendMsgStatus, _> = decode_answer(&answer);
        let Err(LiteError::LiteServer { code, message }) = result else {
            panic!("the captured answer is a liteserver error");
        };
        assert_eq!(code, 0);
        assert_eq!(message, MAINNET_SEND_REFUSAL);

        // And that refusal is not the one that means the opposite of what it reads as.
        assert!(matches!(
            name_a_duplicate(LiteError::LiteServer { code, message }),
            LiteError::LiteServer { .. }
        ));
    }

    #[test]
    fn a_duplicate_refusal_is_named_rather_than_left_as_a_failure() {
        // The wording the reference node reaches the wire with: the phrase it raises,
        // behind the sentence it prefixes onto it before answering.
        let error = LiteError::LiteServer {
            code: 0,
            message: "cannot send external message : duplicate message".to_owned(),
        };
        let named = name_a_duplicate(error);
        assert!(matches!(
            named,
            LiteError::DuplicateSend { code: 0, ref message }
                if message == "cannot send external message : duplicate message"
        ));
    }

    #[test]
    fn every_other_refusal_stays_a_plain_server_error() {
        // The failure direction that matters. A real refusal read as a duplicate would
        // report a message as taken when the server threw it away, so the match has to
        // be narrow enough to leave the neighbouring refusals of the same request alone,
        // including one that shares the error code and the word.
        for message in [
            MAINNET_SEND_REFUSAL,
            "cannot apply external message to current state : bad signature",
            "external message too large, rejecting",
            "too many external messages to address 0:0000",
            "duplicate external message broadcast",
            "not ready",
        ] {
            let named = name_a_duplicate(LiteError::LiteServer {
                code: 0,
                message: message.to_owned(),
            });
            assert!(
                matches!(named, LiteError::LiteServer { .. }),
                "`{message}` must stay a plain server error"
            );
        }
    }

    #[test]
    fn a_wire_block_id_maps_to_the_domain_form() {
        let wire = wire::BlockIdExt {
            workchain: -1,
            shard: 0x8000_0000_0000_0000,
            seqno: 42,
            root_hash: [1; 32],
            file_hash: [2; 32],
        };
        let domain: BlockIdExt = wire.into();
        assert_eq!(domain.workchain, -1);
        assert_eq!(domain.shard, 0x8000_0000_0000_0000);
        assert_eq!(domain.seqno, 42_u32);
    }
}
