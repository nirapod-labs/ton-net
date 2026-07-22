// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Nirapod Labs

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

    /// The local clock is far enough behind the chain that freshness cannot be judged.
    ///
    /// Validators do not sign blocks from the future, so a proven block well ahead of the
    /// local clock places the fault on this side. It is reported rather than ignored
    /// because the freshness check is what separates a current block from a genuine old
    /// one replayed, and a clock this wrong silently switches it off. The remedy is a
    /// correct clock, not another server.
    #[error("the local clock is {by_seconds}s behind the chain, past the {tolerated_seconds}s tolerated")]
    ClockBehind {
        /// How far the proven block is ahead of the local clock.
        by_seconds: u64,
        /// The drift that is tolerated before this is reported.
        tolerated_seconds: u64,
    },

    /// The session lost its place in the byte stream and cannot be used again.
    ///
    /// The ADNL ciphers are a counter the two ends advance in step, so a frame that only
    /// half moved leaves this side unable to read anything further. Abandoning a call at
    /// its deadline is one way to get here. A caller opens a new client; retrying on this
    /// one fails the same way every time.
    #[error("the connection lost its place and has to be reopened")]
    ConnectionLost,
}

/// The stable name for a kind of failure, for a caller that has to branch on one.
///
/// [`Error`] is `#[non_exhaustive]`, so outside this crate it cannot be matched to the
/// end, and a caller who tried would be writing a wildcard arm that silently swallows
/// whatever is added next. This is the type to match on instead: the variant set is what
/// callers are promised, and [`as_str`](ErrorCode::as_str) is the same name spelled for a
/// language that has no enums.
///
/// # Why it lives here and not in each binding
///
/// Which failure occurred decides what a caller does next, and two of the answers are
/// opposites. A transport failure means the socket dropped and the server may be fine, so
/// trying again is right. A proof failure means the server did not prove its answer, so
/// asking it again is the reverse of what this library is for.
///
/// That distinction has to reach every language this library is bound into, spelled the
/// same way. Held in a binding it is one `match` per binding, drifting as each is
/// written, and a caller who learns `PROOF` in JavaScript meets something else in Swift.
/// Held here, a binding maps rather than invents.
///
/// The strings are a compatibility surface: they are what a caller compares against, so
/// they are fixed once published, and renaming one breaks a caller no compiler warns.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum ErrorCode {
    /// A socket could not connect, read, or write. The server may be fine.
    Transport,
    /// The ADNL handshake failed: the configured key is not the key that answered.
    Handshake,
    /// A call passed its deadline.
    Timeout,
    /// The connection lost its place in the cipher stream and cannot be reused.
    ConnectionLost,
    /// The liteserver answered with an error of its own.
    LiteServer,
    /// Bytes that did not read, from a call that verified nothing.
    Decode,
    /// An address that is not one.
    Address,
    /// A network configuration that could not be used.
    Config,
    /// A cell or bag of cells that is not well formed.
    Cell,
    /// A server did not prove its answer. Asking it again is not the repair.
    Proof,
    /// A walk toward the head could not be completed or checked.
    Sync,
    /// The proven head is older than the caller allowed.
    Stale,
    /// The local clock is far enough behind the chain that freshness cannot be judged.
    ClockBehind,
    /// An argument refused before any call was made.
    ///
    /// No [`Error`] carries this: the failure is the caller's rather than the network's,
    /// and it happens above this crate. It is named here anyway, because a binding that
    /// validates its own arguments needs a spelling for it, and the point of this type is
    /// that the spelling is not invented once per language.
    InvalidArgument,
}

impl ErrorCode {
    /// The stable name, for a binding whose language has no enums.
    ///
    /// Upper case with underscores, the form the Node binding already publishes in its
    /// message prefix.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Transport => "TRANSPORT",
            Self::Handshake => "HANDSHAKE",
            Self::Timeout => "TIMEOUT",
            Self::ConnectionLost => "CONNECTION_LOST",
            Self::LiteServer => "LITESERVER",
            Self::Decode => "DECODE",
            Self::Address => "ADDRESS",
            Self::Config => "CONFIG",
            Self::Cell => "CELL",
            Self::Proof => "PROOF",
            Self::Sync => "SYNC",
            Self::Stale => "STALE",
            Self::ClockBehind => "CLOCK_BEHIND",
            Self::InvalidArgument => "INVALID_ARGUMENT",
        }
    }
}

impl std::fmt::Display for ErrorCode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

impl Error {
    /// Which kind of failure this is, as a name a caller can branch on.
    ///
    /// The match below is exhaustive on purpose. `#[non_exhaustive]` binds callers
    /// outside this crate and not this file, so a variant added without a code here fails
    /// to compile rather than reaching a caller unnamed. That is the whole mechanism:
    /// before this existed the mapping was a wildcard inside the Node binding, and a new
    /// variant would have arrived in JavaScript as `UNKNOWN`.
    #[must_use]
    pub fn code(&self) -> ErrorCode {
        match self {
            Self::Transport(_) => ErrorCode::Transport,
            Self::Handshake => ErrorCode::Handshake,
            Self::Timeout => ErrorCode::Timeout,
            Self::ConnectionLost => ErrorCode::ConnectionLost,
            Self::LiteServer { .. } => ErrorCode::LiteServer,
            Self::Decode(_) => ErrorCode::Decode,
            Self::Address(_) => ErrorCode::Address,
            Self::Config(_) => ErrorCode::Config,
            Self::Cell(_) => ErrorCode::Cell,
            Self::Proof(_) => ErrorCode::Proof,
            Self::Sync(_) => ErrorCode::Sync,
            Self::Stale { .. } => ErrorCode::Stale,
            Self::ClockBehind { .. } => ErrorCode::ClockBehind,
        }
    }

    /// Classifies a block-structure failure from a read that checked nothing.
    ///
    /// The same [`BlockError`](ton_net_block::BlockError) means two different things
    /// depending on which call produced it, and the difference is what a caller acts on.
    /// Out of the proof engine it is a server that did not prove its answer, and the
    /// conversion below says so. Out of `Client::account_reported` there was no proof to
    /// fail, so the same failure is only bytes that did not read, and calling it a proof
    /// failure would report a check that never ran.
    pub(crate) fn decoding(error: ton_net_block::BlockError) -> Self {
        Self::Cell(error.to_string())
    }
}

impl From<ton_net_block::BlockError> for Error {
    /// Every way the proof engine fails is a proof failure, bytes that are not cells
    /// included.
    ///
    /// The tempting split is to call unparsable bytes a decode failure, on the reasoning
    /// that they failed before any proof was in question. They did not: the bytes are the
    /// server's proof, and the engine parses them with no precondition, so four bytes of
    /// junk in a shard proof is a server failing to prove its answer in the cheapest way
    /// available. A caller deciding whether to keep asking this server needs both to
    /// arrive as the same kind of failure.
    ///
    /// A read that verified nothing must not use this. It has a classifier of its own, so
    /// a failure out of one stays a failure to read bytes.
    fn from(error: ton_net_block::BlockError) -> Self {
        Self::Proof(error.to_string())
    }
}

impl From<ton_net_adnl::TransportError> for Error {
    fn from(error: ton_net_adnl::TransportError) -> Self {
        // A connect timeout reads as unreachable at this layer: the deadline for a whole
        // call is separate and surfaces as `Timeout`.
        Self::Transport(error.to_string())
    }
}

impl From<ton_net_adnl::AdnlError> for Error {
    fn from(error: ton_net_adnl::AdnlError) -> Self {
        use ton_net_adnl::AdnlError;
        match error {
            AdnlError::Transport(transport) => transport.into(),
            AdnlError::Handshake(_) => Self::Handshake,
            // Kept apart from the rest because the remedy differs: this connection is
            // finished and no retry on it will work, where a framing failure may be one
            // bad answer.
            AdnlError::Desynchronized => Self::ConnectionLost,
            // A framing, checksum, or malformed-message failure is a decode failure at
            // this layer.
            other => Self::Decode(other.to_string()),
        }
    }
}

impl From<ton_net_lite::LiteError> for Error {
    fn from(error: ton_net_lite::LiteError) -> Self {
        use ton_net_lite::LiteError;
        match error {
            LiteError::Adnl(adnl) => adnl.into(),
            LiteError::LiteServer { code, message } => Self::LiteServer { code, message },
            LiteError::Decode(decode) => Self::Decode(decode.to_string()),
            other => Self::Decode(other.to_string()),
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
            BlockError::Cell(ton_net_cell::CellError::LabelTooLong),
            // Bytes that are not cells belong on this list too. The engine parses the
            // proof with no precondition, so four bytes of junk where a shard proof
            // should be is a server failing to prove its answer in the cheapest way
            // there is, and a caller weighing whether to keep asking this server has to
            // see it alongside the rest.
            BlockError::Cell(ton_net_cell::CellError::NotABagOfCells),
            BlockError::Cell(ton_net_cell::CellError::Truncated),
        ] {
            let mapped = Error::from(failure.clone());
            assert!(
                matches!(mapped, Error::Proof(_)),
                "{failure:?} became {mapped:?}"
            );
        }
    }

    #[test]
    fn a_read_that_checked_nothing_reports_no_proof_failure() {
        // The mirror of the rule above. `account_reported` verifies nothing, so the same
        // failure out of it is bytes that did not read, and calling it a proof failure
        // would report a check that never ran.
        for failure in [
            BlockError::Malformed("account address"),
            BlockError::Cell(ton_net_cell::CellError::NotABagOfCells),
        ] {
            let mapped = Error::decoding(failure.clone());
            assert!(
                matches!(mapped, Error::Cell(_)),
                "{failure:?} became {mapped:?}"
            );
        }
    }
}
