//! ADNL message-envelope TL types.
//!
//! These are the outer envelope an ADNL frame carries. A client sends a
//! [`Message::Query`] and the server replies with a [`Message::Answer`] echoing the
//! same `query_id`. [`PublicKey`] is the key form the handshake hashes into a
//! server key id.

use tl_proto::{TlRead, TlWrite};

/// A public key in ADNL's `PublicKey` family: the ed25519 variant.
///
/// Serializing this and hashing the bytes with SHA-256 yields a peer's key id, the
/// value the ADNL handshake addresses the server by.
#[derive(TlRead, TlWrite, Debug, Clone, PartialEq, Eq)]
#[tl(boxed, id = 0x4813b4c6)]
pub struct PublicKey {
    /// The 32-byte ed25519 public key.
    pub key: [u8; 32],
}

/// An `adnl.Message`: the envelope carried inside an ADNL frame.
///
/// The first release uses the query and answer constructors. A query pairs a
/// caller-chosen `query_id` with an opaque request payload; the answer returns the
/// same `query_id` with the response payload, so a caller can match a reply to its
/// request.
#[derive(TlRead, TlWrite, Debug, Clone, PartialEq, Eq)]
#[tl(boxed)]
pub enum Message {
    /// A query: a `query_id` and the serialized request bytes. For the liteserver
    /// path the request is a serialized [`crate::lite::Query`].
    #[tl(id = 0xb48bf97a)]
    Query {
        /// A caller-chosen 32-byte id the matching answer echoes.
        query_id: [u8; 32],
        /// The serialized request payload.
        query: Vec<u8>,
    },
    /// An answer: the `query_id` copied from the query, and the serialized response.
    #[tl(id = 0x0fac8416)]
    Answer {
        /// The `query_id` copied from the query this answers.
        query_id: [u8; 32],
        /// The serialized response payload.
        answer: Vec<u8>,
    },
}
