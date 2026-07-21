//! Checking a read that was fetched separately from the check.

use ton_net_block::{proof, AccountRead};

use crate::error::Error;
use crate::Account;

/// Proves an account read against the block hash the read was checked to.
///
/// [`Client::account`](crate::Client::account) walks to a block it proves and checks
/// against it in one call, and is what most callers want. This is the same check as a
/// standalone function, for the case where the bytes and the anchor arrive separately:
/// bytes fetched now with [`Client::account_state`](crate::Client::account_state) and an
/// anchor that turns up later, or bytes handed over by something that is not this client
/// at all.
///
/// The check is pure. It touches no socket and depends on nothing but its arguments, so
/// the same bytes always give the same answer.
///
/// # Errors
///
/// Returns [`Error::Proof`] if a proof does not root at the trusted hash or the account
/// does not bind to it, and [`Error::Cell`] if the bytes are not cells at all.
///
/// # Example
///
/// ```no_run
/// use ton_net::{AccountRead, Address, Client, Config};
///
/// # async fn run() -> Result<(), ton_net::Error> {
/// # let mut client = Client::connect(&Config::mainnet()).await?;
/// # let trusted = client.masterchain_info().await?.into_value().last;
/// let address = Address::parse("-1:3333333333333333333333333333333333333333333333333333333333333333")?;
/// let reported = client.account_state(&address, &trusted).await?;
/// let state = reported.value();
///
/// let read = AccountRead::masterchain(
///     &trusted.root_hash,
///     address.account_id(),
///     reported.proof(),
///     &state.state,
/// );
/// let account = ton_net::verify_account(&read)?;
/// # Ok(())
/// # }
/// ```
pub fn verify_account(read: &AccountRead<'_>) -> Result<Account, Error> {
    Ok(proof::verify_account(read)?)
}
