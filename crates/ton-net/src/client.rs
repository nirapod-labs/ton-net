//! The client: one ADNL channel to one liteserver, with reads over it.

use std::fmt;
use std::future::Future;
use std::time::Duration;

use ton_net_adnl::TcpTransport;
use ton_net_block::{proof, Account, AccountRead};
use ton_net_lite::{
    AccountId, AccountState, BlockIdExt, LiteClient, LiteError, MasterchainInfo, ServerReported,
};

use crate::{Address, Config, Error, Verified};

/// The deadline for one read, after which the call returns [`Error::Timeout`].
const CALL_TIMEOUT: Duration = Duration::from_secs(15);

/// The workchain id of the masterchain, whose accounts need no shard proof.
const MASTERCHAIN: i32 = -1;

/// A connection to a single TON liteserver.
///
/// A `Client` owns one ADNL channel to one liteserver and serves reads over it.
///
/// Reads come in two kinds and the return type says which. A [`ServerReported`] value is
/// the server's word, believed because the server said so. A [`Verified`] value was
/// checked against a block hash the caller supplied, and could not have been produced any
/// other way. Nothing converts one into the other.
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

    /// Reads an account at the current masterchain head and decodes it.
    ///
    /// Reads the head first, then the account at that block. The value is the server's
    /// word: the proofs it sent are carried along unchecked. To check them, use
    /// [`account_verified`](Self::account_verified) with a block hash from a source the
    /// caller trusts.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Timeout`] if a query does not complete in time, [`Error::LiteServer`]
    /// if the server returns an error, [`Error::Decode`] if a response does not decode,
    /// [`Error::Cell`] if the account state does not read as an account, or
    /// [`Error::Transport`] on a socket failure.
    pub async fn account(&mut self, address: &Address) -> Result<ServerReported<Account>, Error> {
        let head = self.masterchain_info().await?;
        let reported = self.account_state(address, &head.value().last).await?;
        // Decoding does not make the value any more believed, so it stays wrapped.
        Ok(reported.try_map(|state| Account::decode(&state.state))?)
    }

    /// Reads an account's raw state and proofs at a given block.
    ///
    /// The bytes come back as the server sent them, unchecked and undecoded. This is the
    /// way out for a caller who wants to keep the proofs, check them elsewhere, or check
    /// them against an anchor obtained later.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Timeout`] if the query does not complete in time,
    /// [`Error::LiteServer`] if the server returns an error, [`Error::Decode`] if the
    /// response does not decode, or [`Error::Transport`] on a socket failure.
    pub async fn account_state(
        &mut self,
        address: &Address,
        block: &BlockIdExt,
    ) -> Result<ServerReported<AccountState>, Error> {
        let account = AccountId {
            workchain: address.workchain(),
            id: *address.account_id(),
        };
        bounded(self.lite.account_state(block, &account)).await
    }

    /// Reads an account at a block the caller trusts, and proves it belongs to that block.
    ///
    /// The proofs are checked against `trusted`'s root hash: for an account outside the
    /// masterchain the shard block holding it is derived from the masterchain state rather
    /// than taken from what the server named, and the state bytes are bound to the account
    /// the proof carries. An account the block's state does not hold comes back as
    /// [`AccountStatus::Nonexistent`](ton_net_block::AccountStatus::Nonexistent), which is
    /// a proved answer rather than a failure. An account the proof declines to cover is a
    /// failure.
    ///
    /// `trusted` is the one input taken on faith, and taking it from
    /// [`masterchain_info`](Self::masterchain_info) on this same client proves nothing:
    /// that only shows the server agrees with itself. It has to come from somewhere the
    /// caller trusts independently.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Proof`] if a proof does not check out or the account does not bind
    /// to `trusted`, [`Error::Cell`] if the bytes are not cells, or [`Error::Timeout`],
    /// [`Error::LiteServer`], [`Error::Decode`], or [`Error::Transport`] as the read
    /// fails.
    pub async fn account_verified(
        &mut self,
        address: &Address,
        trusted: &BlockIdExt,
    ) -> Result<Verified<Account>, Error> {
        let reported = self.account_state(address, trusted).await?;
        let anchor = trusted.root_hash;
        let workchain = address.workchain();
        let state = reported.value();

        let read = if workchain == MASTERCHAIN {
            AccountRead::masterchain(
                &anchor,
                address.account_id(),
                reported.proof(),
                &state.state,
            )
        } else {
            AccountRead::in_shard(
                &anchor,
                workchain,
                address.account_id(),
                &state.shard_proof,
                reported.proof(),
                &state.state,
            )
        };

        let account = proof::verify_account(&read)?;
        Ok(Verified::new(account, trusted.clone()))
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
