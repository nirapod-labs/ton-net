//! An account, decoded from the state cell a liteserver returns.

use ton_net_cell::{parse_boc, Cell, Slice};

use crate::coins::Coins;
use crate::error::BlockError;

/// An account's status, with the contents that only some statuses have.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum AccountStatus {
    /// The account does not exist at this block. Its balance is zero.
    ///
    /// On TON an address always exists as a name; this means nothing has been stored
    /// under it, not that the address is invalid.
    Nonexistent,

    /// The account holds a balance but has no code or data yet.
    ///
    /// An address that has received TON but never been deployed is in this state.
    Uninit,

    /// The account was frozen for unpaid storage, leaving only the hash of its state.
    Frozen {
        /// The hash of the state the account had when it was frozen.
        state_hash: [u8; 32],
    },

    /// The account is deployed and running.
    Active {
        /// The contract code, absent only in a malformed account.
        code: Option<Cell>,
        /// The contract data, absent only in a malformed account.
        data: Option<Cell>,
    },
}

/// An account as it stands at one block.
///
/// Decode one with [`Account::decode`] from the state bytes a liteserver returns. The
/// value says nothing about whether it was proved; that is the caller's to track.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct Account {
    /// The account balance.
    pub balance: Coins,
    /// The account's status, and its code and data when it has them.
    pub status: AccountStatus,
    /// The logical time just after the account's last transaction.
    ///
    /// This is one past the logical time of that transaction itself, so it will not
    /// equal the last transaction's own logical time as an explorer reports it.
    pub last_trans_lt: u64,
}

impl Account {
    /// An account that does not exist.
    #[must_use]
    pub fn nonexistent() -> Account {
        Account {
            balance: Coins::ZERO,
            status: AccountStatus::Nonexistent,
            last_trans_lt: 0,
        }
    }

    /// Decodes an account from the state bytes a liteserver returned.
    ///
    /// Empty bytes mean the account does not exist at the block that was read, which is
    /// how a liteserver reports an address nothing has been stored under.
    ///
    /// # Errors
    ///
    /// Returns [`BlockError::Cell`] if the bytes are not a bag of cells, or
    /// [`BlockError::Malformed`] if the cell does not read as an account.
    pub fn decode(state: &[u8]) -> Result<Account, BlockError> {
        if state.is_empty() {
            return Ok(Account::nonexistent());
        }
        let roots = parse_boc(state)?;
        let root = roots
            .first()
            .ok_or(BlockError::Malformed("account state has no root cell"))?;
        Account::from_cell(root)
    }

    /// Decodes an account from its state cell.
    ///
    /// # Errors
    ///
    /// Returns [`BlockError::Malformed`] if the cell does not read as an account, or
    /// [`BlockError::Cell`] if it ends early.
    pub fn from_cell(cell: &Cell) -> Result<Account, BlockError> {
        let mut slice = cell.parse();
        if !slice.load_bit()? {
            // account_none: the address holds nothing.
            return Ok(Account::nonexistent());
        }

        skip_address(&mut slice)?;
        skip_storage_info(&mut slice)?;

        let last_trans_lt = slice.load_uint(64)?;
        let balance = Coins::load(&mut slice)?;
        // An extra-currency balance is a dictionary this release steps over rather than
        // decoding; the grams balance is what a read needs.
        let _ = slice.load_maybe_ref()?;
        let status = load_status(&mut slice)?;

        Ok(Account {
            balance,
            status,
            last_trans_lt,
        })
    }

    /// The contract code, when the account is active and has some.
    #[must_use]
    pub fn code(&self) -> Option<&Cell> {
        match &self.status {
            AccountStatus::Active { code, .. } => code.as_ref(),
            _ => None,
        }
    }

    /// The contract data, when the account is active and has some.
    #[must_use]
    pub fn data(&self) -> Option<&Cell> {
        match &self.status {
            AccountStatus::Active { data, .. } => data.as_ref(),
            _ => None,
        }
    }

    /// Whether the account is deployed and running.
    #[must_use]
    pub fn is_active(&self) -> bool {
        matches!(self.status, AccountStatus::Active { .. })
    }

    /// Whether the account exists at all at the block it was read from.
    #[must_use]
    pub fn exists(&self) -> bool {
        !matches!(self.status, AccountStatus::Nonexistent)
    }
}

/// Steps over an account's own address, which the caller already knows.
fn skip_address(slice: &mut Slice<'_>) -> Result<(), BlockError> {
    match slice.load_uint(2)? {
        // addr_std: an eight-bit workchain and a 256-bit account id.
        0b10 => {
            skip_anycast(slice)?;
            slice.skip_bits(8 + 256)?;
        }
        // addr_var: a wider workchain and an account id of a stated length.
        0b11 => {
            skip_anycast(slice)?;
            let len = slice.load_uint(9)? as usize;
            slice.skip_bits(32 + len)?;
        }
        _ => return Err(BlockError::Malformed("account address")),
    }
    Ok(())
}

/// Steps over an address's anycast prefix, which almost no address carries.
fn skip_anycast(slice: &mut Slice<'_>) -> Result<(), BlockError> {
    if slice.load_bit()? {
        let depth = slice.load_uint(5)? as usize;
        slice.skip_bits(depth)?;
    }
    Ok(())
}

/// Steps over the storage statistics that sit between the address and the balance.
///
/// `StorageUsed` carries three counters, cells, bits, and public cells. The public-cells
/// counter has come and gone across TON versions, and getting it wrong shifts everything
/// after it: a decode without it puts `last_paid` decades in the past and the balance
/// becomes noise. Mainnet still carries it, checked against a real account whose balance
/// an independent source reports.
fn skip_storage_info(slice: &mut Slice<'_>) -> Result<(), BlockError> {
    for _ in 0..3 {
        slice.load_var_uint(7)?;
    }
    slice.skip_bits(32)?; // last_paid
    if slice.load_bit()? {
        // due_payment, owed storage fees.
        slice.load_var_uint(16)?;
    }
    Ok(())
}

/// Reads the account state that follows the balance.
fn load_status(slice: &mut Slice<'_>) -> Result<AccountStatus, BlockError> {
    if slice.load_bit()? {
        // account_active: a StateInit holding the code and data.
        if slice.load_bit()? {
            slice.skip_bits(5)?; // split_depth
        }
        if slice.load_bit()? {
            slice.skip_bits(2)?; // special, the tick and tock flags
        }
        let code = slice.load_maybe_ref()?.cloned();
        let data = slice.load_maybe_ref()?.cloned();
        // A library dictionary, stepped over rather than decoded.
        let _ = slice.load_maybe_ref()?;
        return Ok(AccountStatus::Active { code, data });
    }
    if slice.load_bit()? {
        // account_frozen: only the hash of what the state was.
        let bytes = slice.load_bytes(32)?;
        let mut state_hash = [0u8; 32];
        state_hash.copy_from_slice(&bytes);
        return Ok(AccountStatus::Frozen { state_hash });
    }
    // account_uninit: a balance and nothing else.
    Ok(AccountStatus::Uninit)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_state_bytes_are_an_account_that_does_not_exist() {
        let account = Account::decode(&[]).unwrap();
        assert_eq!(account.status, AccountStatus::Nonexistent);
        assert_eq!(account.balance, Coins::ZERO);
        assert_eq!(account.last_trans_lt, 0);
        assert!(!account.exists());
        assert!(!account.is_active());
        assert!(account.code().is_none());
    }

    #[test]
    fn bytes_that_are_not_a_bag_of_cells_are_refused() {
        assert!(matches!(
            Account::decode(&[1, 2, 3, 4]),
            Err(BlockError::Cell(_))
        ));
    }

    #[test]
    fn a_cell_whose_first_bit_is_clear_is_account_none() {
        // One cell, one bit, clear: the account_none constructor.
        let bytes = [
            0xb5, 0xee, 0x9c, 0x72, 0x01, 0x01, 0x01, 0x01, 0x00, 0x03, 0x00, 0x00, 0x01, 0x40,
        ];
        let account = Account::decode(&bytes).unwrap();
        assert_eq!(account.status, AccountStatus::Nonexistent);
    }
}
