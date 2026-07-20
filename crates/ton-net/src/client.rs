//! The client: one ADNL channel to one liteserver, with reads over it.

use std::fmt;
use std::future::Future;
use std::time::Duration;

use ton_net_adnl::TcpTransport;
use ton_net_lite::{
    AccountId, AccountState, LiteClient, LiteError, MasterchainInfo, ServerReported,
};

use crate::{Address, Config, Error};

/// The deadline for one read, after which the call returns [`Error::Timeout`].
const CALL_TIMEOUT: Duration = Duration::from_secs(15);

/// A connection to a single TON liteserver.
///
/// A `Client` owns one ADNL channel to one liteserver and serves reads over it. Reads in
/// this release are not proof-verified; each returns a [`ServerReported`] value.
///
/// A `Client` serializes its queries: overlapping calls on the same client run one after
/// another over the single channel, because each takes `&mut self`. Open more than one
/// client for real concurrency.
pub struct Client {
    lite: LiteClient<TcpTransport>,
}

impl Client {
    /// Connects to a liteserver from the config and completes the ADNL handshake.
    ///
    /// Tries the config's liteservers in turn until one connects and completes a
    /// handshake.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Transport`] if no liteserver is reachable, or [`Error::Handshake`]
    /// if the last one reached rejects the handshake.
    pub async fn connect(config: &Config) -> Result<Client, Error> {
        let mut last_error: Option<Error> = None;
        for server in config.liteservers() {
            let transport = match TcpTransport::connect(&server.addr).await {
                Ok(transport) => transport,
                Err(e) => {
                    last_error = Some(e.into());
                    continue;
                }
            };
            match LiteClient::connect(transport, &server.key).await {
                Ok(lite) => return Ok(Client { lite }),
                Err(e) => last_error = Some(e.into()),
            }
        }
        Err(last_error.unwrap_or_else(|| Error::Config("config has no liteservers".to_string())))
    }

    /// Reads the liteserver's current masterchain head.
    ///
    /// The returned [`MasterchainInfo`] is fully decoded from the wire. It is not
    /// proof-verified.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Timeout`] if the query does not complete in time, [`Error::LiteServer`]
    /// if the server returns an error, [`Error::Decode`] if the response does not decode,
    /// or [`Error::Transport`] on a socket failure.
    pub async fn masterchain_info(&mut self) -> Result<ServerReported<MasterchainInfo>, Error> {
        bounded(self.lite.masterchain_info()).await
    }

    /// Reads an account's raw state at the current masterchain head.
    ///
    /// Reads the head first, then the account at that block. The returned [`AccountState`]
    /// holds the account state as raw bag-of-cells bytes; decoding those into a balance,
    /// code, and data is not part of this release. The value is not proof-verified.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Timeout`] if a query does not complete in time, [`Error::LiteServer`]
    /// if the server returns an error, [`Error::Decode`] if a response does not decode, or
    /// [`Error::Transport`] on a socket failure.
    pub async fn account(
        &mut self,
        address: &Address,
    ) -> Result<ServerReported<AccountState>, Error> {
        let head = self.masterchain_info().await?;
        let account = AccountId {
            workchain: address.workchain(),
            id: *address.account_id(),
        };
        bounded(self.lite.account_state(&head.value().last, &account)).await
    }
}

impl fmt::Debug for Client {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Client").finish_non_exhaustive()
    }
}

/// Runs one liteserver call under the deadline, mapping its error into [`Error`].
async fn bounded<T>(call: impl Future<Output = Result<T, LiteError>>) -> Result<T, Error> {
    match tokio::time::timeout(CALL_TIMEOUT, call).await {
        Ok(result) => result.map_err(Error::from),
        Err(_elapsed) => Err(Error::Timeout),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // A call that never answers must resolve to `Error::Timeout`, never hang. With the
    // clock paused, tokio advances virtual time to the deadline the moment the runtime is
    // otherwise idle, so this proves the bound in real time without a fifteen-second wait.
    #[tokio::test(start_paused = true)]
    async fn a_call_that_never_answers_times_out() {
        let never = std::future::pending::<Result<(), LiteError>>();
        let result: Result<(), Error> = bounded(never).await;
        assert!(matches!(result, Err(Error::Timeout)));
    }

    // A call that answers before the deadline passes its result through untouched.
    #[tokio::test(start_paused = true)]
    async fn a_call_that_answers_is_not_timed_out() {
        let ready = std::future::ready::<Result<u32, LiteError>>(Ok(7));
        assert_eq!(bounded(ready).await.unwrap(), 7);
    }
}
