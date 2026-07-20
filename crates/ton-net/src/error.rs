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
