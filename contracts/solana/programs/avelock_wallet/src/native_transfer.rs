use anchor_lang::prelude::*;
use crate::errors::AvelockError;

/// Internal transfer primitive; the instruction's account constraints and
/// timelock/allowlist checks must run first. All checks precede either write.
pub(crate) fn transfer_lamports(
    vault: &AccountInfo,
    recipient: &AccountInfo,
    amount: u64,
    rent: &Rent,
) -> Result<()> {
    require_keys_neq!(*vault.key, *recipient.key, AvelockError::InvalidDestination);
    let remaining = vault.lamports().checked_sub(amount)
        .ok_or(AvelockError::InsufficientSpendableBalance)?;
    require!(remaining >= rent.minimum_balance(vault.data_len()), AvelockError::InsufficientSpendableBalance);
    let received = recipient.lamports().checked_add(amount)
        .ok_or(AvelockError::ArithmeticOverflow)?;
    // Borrow both before touching either balance. The Solana runtime additionally
    // rolls back the transaction on any error, including account serialization.
    let mut source = vault.try_borrow_mut_lamports()?;
    let mut destination = recipient.try_borrow_mut_lamports()?;
    **source = remaining;
    **destination = received;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::Vault;

    fn run(balance: u64, destination_balance: u64, amount: u64) -> (Result<()>, u64, u64) {
        let key = Pubkey::new_unique();
        let to = Pubkey::new_unique();
        let system = anchor_lang::solana_program::system_program::ID;
        let mut source_balance = balance;
        let mut target_balance = destination_balance;
        let mut data = vec![0u8; Vault::SPACE];
        let mut target_data = [];
        let source = AccountInfo::new(&key, false, true, &mut source_balance, &mut data, &crate::ID, false, 0);
        let target = AccountInfo::new(&to, false, true, &mut target_balance, &mut target_data, &system, false, 0);
        let result = transfer_lamports(&source, &target, amount, &Rent::default());
        (result, source_balance, target_balance)
    }

    #[test]
    fn permits_exact_spendable_balance_and_preserves_rent() {
        let reserve = Rent::default().minimum_balance(Vault::SPACE);
        let (result, source, target) = run(reserve + 100, 20, 100);
        assert!(result.is_ok());
        assert_eq!(source, reserve);
        assert_eq!(target, 120);
    }

    #[test]
    fn preserves_both_balances_when_reserve_would_be_spent() {
        let reserve = Rent::default().minimum_balance(Vault::SPACE);
        for amount in [101, reserve + 100, reserve + 101, u64::MAX] {
            let (result, source, target) = run(reserve + 100, 20, amount);
            assert!(result.is_err());
            assert_eq!(source, reserve + 100);
            assert_eq!(target, 20);
        }
    }

    #[test]
    fn does_not_debit_when_recipient_would_overflow() {
        let balance = Rent::default().minimum_balance(Vault::SPACE) + 100;
        let (result, source, target) = run(balance, u64::MAX, 1);
        assert!(result.is_err());
        assert_eq!(source, balance);
        assert_eq!(target, u64::MAX);
    }

    #[test]
    fn rejects_aliased_accounts_without_changing_balance() {
        let key = Pubkey::new_unique();
        let mut balance = Rent::default().minimum_balance(Vault::SPACE) + 100;
        let original = balance;
        let mut data = vec![0u8; Vault::SPACE];
        let source = AccountInfo::new(&key, false, true, &mut balance, &mut data, &crate::ID, false, 0);
        assert!(transfer_lamports(&source, &source.clone(), 1, &Rent::default()).is_err());
        assert_eq!(balance, original);
    }
}
