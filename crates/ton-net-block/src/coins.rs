//! An amount of TON.

use std::fmt;

use ton_net_cell::Slice;

use crate::error::BlockError;

/// The nanotons in one TON.
const NANOTONS_PER_TON: u128 = 1_000_000_000;

/// An amount of TON, held in nanotons.
///
/// TON amounts are a `VarUInteger 16` on the wire, at most fifteen bytes, so every valid
/// amount fits a `u128`. The type displays as a decimal count of nanotons, which is the
/// form that crosses a language boundary without loss.
///
/// # Examples
///
/// ```
/// use ton_net_block::Coins;
///
/// let amount = Coins::from_nanotons(6_910_657_721_334);
/// assert_eq!(amount.to_string(), "6910657721334");
/// assert_eq!(amount.tons(), 6910);
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct Coins(u128);

impl Coins {
    /// No TON at all.
    pub const ZERO: Coins = Coins(0);

    /// Builds an amount from a count of nanotons.
    #[must_use]
    pub const fn from_nanotons(nanotons: u128) -> Coins {
        Coins(nanotons)
    }

    /// The amount in nanotons.
    #[must_use]
    pub const fn nanotons(self) -> u128 {
        self.0
    }

    /// The amount in whole TON, rounded down.
    ///
    /// This loses the fractional part and is for display only; keep the nanotons for
    /// anything that has to be exact.
    #[must_use]
    pub const fn tons(self) -> u128 {
        self.0 / NANOTONS_PER_TON
    }

    /// Reads an amount from the head of a slice.
    ///
    /// # Errors
    ///
    /// Returns [`BlockError::Cell`] if the slice runs out before the amount is complete.
    pub(crate) fn load(slice: &mut Slice<'_>) -> Result<Coins, BlockError> {
        Ok(Coins(slice.load_var_uint(16)?))
    }
}

impl fmt::Display for Coins {
    /// Writes the amount as a decimal count of nanotons.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl From<u128> for Coins {
    fn from(nanotons: u128) -> Coins {
        Coins(nanotons)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn displays_as_decimal_nanotons() {
        assert_eq!(Coins::ZERO.to_string(), "0");
        assert_eq!(Coins::from_nanotons(1).to_string(), "1");
        // The largest a VarUInteger 16 can carry, fifteen bytes of ones.
        let widest = (1u128 << 120) - 1;
        assert_eq!(Coins::from_nanotons(widest).to_string(), widest.to_string());
    }

    #[test]
    fn whole_tons_round_down() {
        assert_eq!(Coins::from_nanotons(999_999_999).tons(), 0);
        assert_eq!(Coins::from_nanotons(1_000_000_000).tons(), 1);
        assert_eq!(Coins::from_nanotons(6_910_657_721_334).tons(), 6910);
    }
}
