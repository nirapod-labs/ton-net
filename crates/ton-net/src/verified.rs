//! The wrapper that marks a value as proven against a block.

use ton_net_lite::BlockIdExt;

/// A value proven to sit in the state of a block the caller trusts.
///
/// The value's Merkle proofs were checked to root at the [anchor](Self::anchor)'s hash,
/// and the value was bound to that block's state by hash. Nothing the server said was
/// taken on trust along the way, including which shard block held the account.
///
/// # What this does and does not say
///
/// The claim is relative: the value is as trustworthy as the block in its
/// [anchor](Self::anchor), and no more. That block's own worth depends on where it came
/// from. Handing [`account_at`](crate::Client::account_at) a head read from the same
/// server proves only that the server is internally consistent, which a server making
/// things up can also manage. A block from [`Client::sync`](crate::Client::sync), and so
/// from [`Client::account`](crate::Client::account), was walked to from the key block the
/// config pins with a validator signature set checked at every step, and rests on nothing
/// the server chose.
///
/// # Why it cannot be forged
///
/// There is no public constructor. A `Verified<T>` exists only where this crate checked
/// the proofs, so a value of this type in a signature is a claim the type system keeps
/// honest rather than a convention a caller can opt out of.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct Verified<T> {
    value: T,
    anchor: BlockIdExt,
}

impl<T> Verified<T> {
    /// Records that `value` was proven against `anchor`.
    ///
    /// Private on purpose: see the note on the type.
    pub(crate) fn new(value: T, anchor: BlockIdExt) -> Verified<T> {
        Verified { value, anchor }
    }

    /// The verified value.
    #[must_use]
    pub fn value(&self) -> &T {
        &self.value
    }

    /// Consumes the wrapper and returns the verified value.
    #[must_use]
    pub fn into_value(self) -> T {
        self.value
    }

    /// The block the value was proven against.
    #[must_use]
    pub fn anchor(&self) -> &BlockIdExt {
        &self.anchor
    }
}
