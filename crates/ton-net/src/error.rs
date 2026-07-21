//! The facade error type and the mappings from the lower crates into it.

/// The error type for every fallible operation in this crate.
///
/// A closed, `#[non_exhaustive]` enum: variants can be added before 1.0 without a
/// breaking change. The lower crates' narrow errors are mapped into this set.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// A transport failure: a socket could not connect, read, or write.
    #[error("transport: {0}")]
    Transport(String),

    /// The ADNL handshake with a liteserver failed.
    #[error("handshake failed")]
    Handshake,

    /// A query did not complete within its deadline.
    #[error("timed out")]
    Timeout,

    /// The liteserver returned an error response.
    #[error("liteserver error {code}: {message}")]
    LiteServer {
        /// The liteserver error code.
        code: i32,
        /// The liteserver error message.
        message: String,
    },

    /// A wire value could not be decoded, or a frame checksum did not match.
    #[error("decode: {0}")]
    Decode(String),

    /// An address string was not a valid address.
    #[error("address: {0}")]
    Address(String),

    /// A config could not be parsed.
    #[error("config: {0}")]
    Config(String),

    /// A cell, a bag of cells, or a structure built from them could not be read.
    #[error("cell: {0}")]
    Cell(String),

    /// A proof did not check out, or the account did not bind to the trusted block.
    ///
    /// A read that fails this way returns no value at all. There is no partial result and
    /// no unproven fallback: a verified read either proves what it returns or fails.
    #[error("proof: {0}")]
    Proof(String),

    /// A block proof chain did not establish a block to trust.
    ///
    /// Separate from [`Proof`](Self::Proof) because the two fail at different stages. A
    /// proof failure means a server's answer did not match a block the client already
    /// trusts; a sync failure means the client never established that block at all, and
    /// retrying against another server is a reasonable response to one and not the other.
    #[error("sync: {0}")]
    Sync(String),

    /// The newest block the server could prove is older than the freshness bound.
    ///
    /// The one failure here where the server may be honest and merely behind. A liteserver
    /// can serve a real, fully proved block that is simply old, and nothing inside a proof
    /// says when it was served.
    #[error("the proven head is {age_seconds}s old, past the {limit_seconds}s bound")]
    Stale {
        /// How far behind the local clock the proven head is.
        age_seconds: u64,
        /// The bound that was exceeded, from [`crate::Config::max_head_age`].
        limit_seconds: u64,
    },
}

impl From<ton_net_block::BlockError> for Error {
    fn from(error: ton_net_block::BlockError) -> Self {
        use ton_net_block::BlockError;
        match error {
            // Bytes that are not cells at all failed before any proof was in question.
            BlockError::Cell(cell) => Error::Cell(cell.to_string()),
            // Everything else was reached while checking a proof, so it failed as one: a
            // structure that does not read is a proof that does not check out.
            other => Error::Proof(other.to_string()),
        }
    }
}

impl From<ton_net_adnl::TransportError> for Error {
    fn from(error: ton_net_adnl::TransportError) -> Self {
        // A connect timeout reads as unreachable at this layer: the deadline for a whole
        // call is separate and surfaces as `Timeout`.
        Error::Transport(error.to_string())
    }
}

impl From<ton_net_adnl::AdnlError> for Error {
    fn from(error: ton_net_adnl::AdnlError) -> Self {
        use ton_net_adnl::AdnlError;
        match error {
            AdnlError::Transport(transport) => transport.into(),
            AdnlError::Handshake(_) => Error::Handshake,
            // A framing, checksum, or malformed-message failure is a decode failure at
            // this layer.
            other => Error::Decode(other.to_string()),
        }
    }
}

impl From<ton_net_lite::LiteError> for Error {
    fn from(error: ton_net_lite::LiteError) -> Self {
        use ton_net_lite::LiteError;
        match error {
            LiteError::Adnl(adnl) => adnl.into(),
            LiteError::LiteServer { code, message } => Error::LiteServer { code, message },
            LiteError::Decode(decode) => Error::Decode(decode.to_string()),
            other => Error::Decode(other.to_string()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::Error;
    use ton_net_block::BlockError;

    #[test]
    fn a_failed_proof_never_arrives_as_something_softer() {
        // Every way a proof can fail has to reach the caller as a proof failure. Any of
        // these landing in `Decode` or `Cell` would read as bad bytes rather than as a
        // server that did not prove its answer.
        for failure in [
            BlockError::NotAMerkleProof,
            BlockError::ProofInconsistent,
            BlockError::ProofNotAnchored,
            BlockError::NotCovered,
            BlockError::NotBound,
            BlockError::WrongConstructor { expected: "block" },
            BlockError::Malformed("shard state"),
            BlockError::LabelTooLong,
        ] {
            let mapped = Error::from(failure.clone());
            assert!(
                matches!(mapped, Error::Proof(_)),
                "{failure:?} became {mapped:?}"
            );
        }
    }

    #[test]
    fn bytes_that_are_not_cells_arrive_as_a_cell_failure() {
        // This one failed before a proof was in question, so calling it a proof failure
        // would point a caller at the wrong thing.
        let mapped = Error::from(BlockError::Cell(ton_net_cell::CellError::NotABagOfCells));
        assert!(matches!(mapped, Error::Cell(_)), "{mapped:?}");
    }
}
