//! The client: one ADNL channel to one liteserver, with reads over it.

use std::fmt;
use std::future::Future;
use std::time::Duration;

use ton_net_adnl::TcpTransport;
use ton_net_block::{proof, verify_chain, Account, AccountRead};
use ton_net_lite::{
    AccountId, AccountState, BlockIdExt, BlockLink, LiteClient, LiteError, MasterchainInfo,
    PartialBlockProof, ServerReported,
};

use crate::sync::{self, SyncReport};
use crate::{Address, Config, Error, Verified};

/// The deadline for one read, after which the call returns [`Error::Timeout`].
const CALL_TIMEOUT: Duration = Duration::from_secs(15);

/// The deadline for one block-proof reply, which is a different size of thing.
///
/// An account read is a few kilobytes. One round of a proof chain is closer to seven
/// hundred, because every link in it carries a configuration proof exposing a validator
/// set of several hundred entries. Holding both to the same deadline means either
/// refusing an honest proof on a slow link or letting a dead read hang.
const PROOF_TIMEOUT: Duration = Duration::from_secs(60);

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
    /// The key block trust rests on. `None` until a sync has established one.
    anchor: Option<BlockIdExt>,
    /// The block a cold sync starts walking from, as the config named it.
    init_block: Option<BlockIdExt>,
    /// How far behind the local clock a proven head may be.
    max_head_age: u32,
}

impl Client {
    /// Connects to a liteserver from the config and completes the ADNL handshake.
    ///
    /// Tries the config's liteservers in turn until one connects and completes a
    /// handshake. Nothing is proved yet: the client has no anchor until
    /// [`sync`](Self::sync) establishes one.
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
                Ok(lite) => {
                    return Ok(Client {
                        lite,
                        anchor: None,
                        init_block: config.init_block().cloned(),
                        max_head_age: config.max_head_age(),
                    })
                }
                Err(e) => last_error = Some(e.into()),
            }
        }
        Err(last_error.unwrap_or_else(|| Error::Config("config has no liteservers".to_string())))
    }

    /// Connects and starts the walk from a block the caller already trusts.
    ///
    /// `anchor` must be a masterchain key block. It is the client's root of trust:
    /// everything the client goes on to believe is derived from it, so it is worth
    /// exactly what the storage it came from is worth. Anything that can write to where
    /// a caller keeps one can choose what this client believes.
    ///
    /// A block from a previous run's [`anchor`](Self::anchor) makes this sync short,
    /// which is the whole reason the anchor is handed back.
    ///
    /// # Errors
    ///
    /// As [`connect`](Self::connect), plus [`Error::Sync`] if the server cannot prove a
    /// chain from `anchor`, and [`Error::Stale`] if what it leads to is too old.
    pub async fn connect_from(config: &Config, anchor: &BlockIdExt) -> Result<Client, Error> {
        let mut client = Client::connect(config).await?;
        client.anchor = Some(anchor.clone());
        client.sync().await?;
        Ok(client)
    }

    /// The key block the client's trust currently rests on, if a sync has run.
    ///
    /// Saving this and handing it to [`connect_from`](Self::connect_from) on a later run
    /// makes that run's sync short. It is a public block identity and holds no secret,
    /// but it is a root of trust, so where it is kept is a decision the caller's own
    /// threat model makes. This library stores nothing and picks no location.
    #[must_use]
    pub fn anchor(&self) -> Option<&BlockIdExt> {
        self.anchor.as_ref()
    }

    /// Walks the anchor forward to the network's current head.
    ///
    /// Without an anchor the walk starts at the config's init block, which is a first
    /// sync and costs a run over every key block published since that block: about a
    /// couple of minutes and fifty megabytes against mainnet in July 2026. With one it is
    /// a few links.
    ///
    /// The head in the returned [`SyncReport`] is proved and then the client forgets it.
    /// What the client keeps is the last key block on the way, because that is the only
    /// kind of block a later chain can continue from. Read [`anchor`](Self::anchor) after
    /// this to save it.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Config`] if there is neither an anchor nor an init block,
    /// [`Error::Sync`] if the proof chain does not check out or the server will not
    /// finish it, [`Error::Stale`] if the head it leads to is older than the config's
    /// freshness bound, or the transport errors.
    pub async fn sync(&mut self) -> Result<SyncReport, Error> {
        let start = match (&self.anchor, &self.init_block) {
            (Some(anchor), _) => anchor.clone(),
            (None, Some(init)) => init.clone(),
            (None, None) => {
                return Err(Error::Config(
                    "config names no init block to start a sync from".to_string(),
                ))
            }
        };

        // The head is the server's word about where the chain ends, used only as the
        // target to ask for. Every block on the way to it is proved, including this one,
        // so a server naming a block that does not exist fails the walk rather than
        // steering it.
        let target = self.masterchain_info().await?.into_value().last;
        // A server whose head is not ahead of what the client already trusts has nothing
        // to prove, and there is no way to establish that its block is current without a
        // chain to it. That is a refusal rather than a quiet success at the old block.
        if target.seqno <= start.seqno {
            return Err(Error::Sync(format!(
                "the server's head at {} is not ahead of the trusted block at {}",
                target.seqno, start.seqno
            )));
        }

        let mut anchor = start.clone();
        let mut trusted_key_block = start;
        let mut walk = sync::Walk::new();
        loop {
            let reply = within(PROOF_TIMEOUT, self.lite.block_proof(&anchor, &target)).await?;
            sync::within_bounds(&reply)?;
            walk.round(reply.steps.len())?;

            let proven = verify_chain(&(&anchor).into(), &reply)
                .map_err(|failure| Error::Sync(failure.to_string()))?;
            let reached = BlockIdExt::from(proven.id);
            sync::advanced(&anchor, &reached)?;

            // Every link's key-block flag was checked against the destination's own
            // header, so after the chain checks out the flag is proved rather than
            // claimed and the last key block in the run can be taken from it.
            if let Some(key_block) = last_key_block(&reply) {
                trusted_key_block = key_block;
            }
            anchor = reached;

            if reply.complete {
                sync::fresh_enough(proven.gen_utime, self.max_head_age)?;
                self.anchor = Some(trusted_key_block);
                let (links, rounds) = walk.cost();
                return Ok(SyncReport {
                    head: anchor,
                    links,
                    rounds,
                });
            }
            // An unfinished chain has to be continued from where it stopped, and only a
            // key block carries the validator set that makes the next step checkable.
            if !proven.key_block {
                return Err(Error::Sync(
                    "an unfinished chain stopped at a block no chain can continue from".to_string(),
                ));
            }
        }
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

/// The last block in a checked chain that a later chain can continue from.
///
/// Only safe to read after [`verify_chain`] has returned, because that is what ties each
/// link's key-block flag to the destination block's own header.
fn last_key_block(reply: &PartialBlockProof) -> Option<BlockIdExt> {
    reply.steps.iter().rev().find_map(|step| match step {
        BlockLink::Forward {
            to_key_block: true,
            to,
            ..
        } => Some(to.clone().into()),
        _ => None,
    })
}

/// Runs one liteserver read under the ordinary deadline.
async fn bounded<T>(call: impl Future<Output = Result<T, LiteError>>) -> Result<T, Error> {
    within(CALL_TIMEOUT, call).await
}

/// Runs one liteserver call under a given deadline, mapping its error into [`Error`].
async fn within<T>(
    deadline: Duration,
    call: impl Future<Output = Result<T, LiteError>>,
) -> Result<T, Error> {
    match tokio::time::timeout(deadline, call).await {
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
