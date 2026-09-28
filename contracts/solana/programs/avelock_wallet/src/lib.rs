// ============================================================
// Avelock Wallet — Solana port
// Self-custody vault with on-chain withdrawal delays.
// https://github.com/avelock/AvelockWallet
// ============================================================
//
// Port of avelock-wallet/src/{AvelockWallet.sol,extensions/
// AvelockSecurityExtension.sol}. See state.rs for the account-model
// notes (why the two-contract EVM split becomes two account types here
// instead of two programs, and why NFTs need no separate code path).
//
// Local host tests cover transfer accounting and generated account metadata.
// Existing localnet integration tests require a matching deployed build and
// were not rerun as part of the no-deployment fixes. See README.md for scope.

use anchor_lang::prelude::*;
use anchor_spl::token::{self, Mint, Token, TokenAccount, Transfer};
use anchor_spl::associated_token::AssociatedToken;

pub mod errors;
mod native_transfer;
pub mod state;

use errors::AvelockError;
use state::*;

declare_id!("9r172eBe2XJ9PPFH8rmb6XbxNkrNLkMnqBZmSfCwUiXD");

#[program]
pub mod avelock_wallet {
    use super::*;

    /// Creates the Vault and its one permanent SecurityExtension in a
    /// single instruction — the Solana equivalent of AvelockWallet's
    /// constructor deploying its own AvelockSecurityExtension. There is
    /// no separate "install the module" step to skip or get wrong.
    pub fn initialize_vault(
        ctx: Context<InitializeVault>,
        withdrawal_delay: i64,
        address_delay: i64,
        confirmation_window: i64,
        policy_delay: i64,
        min_withdrawal_delay: i64,
        min_address_delay: i64,
    ) -> Result<()> {
        require!(min_withdrawal_delay > 0 && min_address_delay > 0, AvelockError::ZeroMinimum);
        require!(withdrawal_delay >= min_withdrawal_delay, AvelockError::BelowImmutableMinimum);
        require!(address_delay >= min_address_delay, AvelockError::BelowImmutableMinimum);
        validate_param(PARAM_WITHDRAWAL_DELAY, withdrawal_delay)?;
        validate_param(PARAM_ADDRESS_DELAY, address_delay)?;
        validate_param(PARAM_CONFIRMATION_WINDOW, confirmation_window)?;
        validate_param(PARAM_POLICY_DELAY, policy_delay)?;

        let vault = &mut ctx.accounts.vault;
        vault.owner = ctx.accounts.owner.key();
        vault.security_extension = ctx.accounts.extension.key();
        vault.bump = ctx.bumps.vault;

        let extension = &mut ctx.accounts.extension;
        extension.wallet = vault.key();
        extension.withdrawal_delay = withdrawal_delay;
        extension.address_delay = address_delay;
        extension.confirmation_window = confirmation_window;
        extension.policy_delay = policy_delay;
        extension.min_withdrawal_delay = min_withdrawal_delay;
        extension.min_address_delay = min_address_delay;
        extension.next_request_id = 0;
        extension.pending = [PendingParamChange::default(); PARAM_COUNT];
        extension.bump = ctx.bumps.extension;
        extension.guards = [GuardSlot::default(); MAX_GUARDS];
        // Lifting a lock waits at least as long as a withdrawal would.
        extension.lock_delay = withdrawal_delay.max(DEFAULT_LOCK_DELAY);
        extension.locked = false;
        extension.unlock_after = 0;
        extension.lock_epoch = 0;
        extension.lock_times = [0; LOCK_HISTORY];

        emit!(VaultInitialized {
            vault: vault.key(),
            extension: extension.key(),
            owner: vault.owner,
        });
        Ok(())
    }

    // ---------------------------------------------------------------
    // Policy changes — every actual change waits the *current* policy
    // delay, including increases that could otherwise harm availability
    // if applied instantly. Mirrors AvelockSecurityExtension.setX/
    // applyParamChange/cancelParamChange exactly.
    // ---------------------------------------------------------------

    pub fn set_withdrawal_delay(ctx: Context<OwnerOnly>, new_value: i64) -> Result<()> {
        let extension = &mut ctx.accounts.extension;
        require!(!extension.locked, AvelockError::VaultLocked);
        require!(new_value >= extension.min_withdrawal_delay, AvelockError::BelowImmutableMinimum);
        propose_change(extension, PARAM_WITHDRAWAL_DELAY, new_value, extension.withdrawal_delay)
    }

    pub fn set_address_delay(ctx: Context<OwnerOnly>, new_value: i64) -> Result<()> {
        let extension = &mut ctx.accounts.extension;
        require!(!extension.locked, AvelockError::VaultLocked);
        require!(new_value >= extension.min_address_delay, AvelockError::BelowImmutableMinimum);
        propose_change(extension, PARAM_ADDRESS_DELAY, new_value, extension.address_delay)
    }

    pub fn set_confirmation_window(ctx: Context<OwnerOnly>, new_value: i64) -> Result<()> {
        let extension = &mut ctx.accounts.extension;
        require!(!extension.locked, AvelockError::VaultLocked);
        propose_change(extension, PARAM_CONFIRMATION_WINDOW, new_value, extension.confirmation_window)
    }

    pub fn set_policy_delay(ctx: Context<OwnerOnly>, new_value: i64) -> Result<()> {
        let extension = &mut ctx.accounts.extension;
        require!(!extension.locked, AvelockError::VaultLocked);
        propose_change(extension, PARAM_POLICY_DELAY, new_value, extension.policy_delay)
    }

    /// The wait before a Panic Lock can be lifted; never below the withdrawal floor.
    pub fn set_lock_delay(ctx: Context<OwnerOnly>, new_value: i64) -> Result<()> {
        let extension = &mut ctx.accounts.extension;
        require!(!extension.locked, AvelockError::VaultLocked);
        require!(new_value >= extension.min_withdrawal_delay, AvelockError::BelowImmutableMinimum);
        propose_change(extension, PARAM_LOCK_DELAY, new_value, extension.lock_delay)
    }

    /// Finalize a queued parameter change once its effective time has passed.
    pub fn apply_param_change(ctx: Context<OwnerOnly>, param: u8) -> Result<()> {
        let extension = &mut ctx.accounts.extension;
        require!(!extension.locked, AvelockError::VaultLocked);
        let idx = param as usize;
        require!(idx < PARAM_COUNT, AvelockError::InvalidParameter);
        let pending = extension.pending[idx];
        require!(pending.exists, AvelockError::NoPendingChange);
        let now = Clock::get()?.unix_timestamp;
        require!(now >= pending.effective_at, AvelockError::ChangeNotReady);

        write_param(extension, param, pending.new_value);
        extension.pending[idx] = PendingParamChange::default();
        emit!(ParamChangeApplied { extension: extension.key(), param, new_value: pending.new_value });
        Ok(())
    }

    /// Cancel a queued parameter change before it takes effect.
    pub fn cancel_param_change(ctx: Context<OwnerOnly>, param: u8) -> Result<()> {
        let extension = &mut ctx.accounts.extension;
        let idx = param as usize;
        require!(idx < PARAM_COUNT, AvelockError::InvalidParameter);
        require!(extension.pending[idx].exists, AvelockError::NoPendingChange);
        extension.pending[idx] = PendingParamChange::default();
        emit!(ParamChangeCancelled { extension: extension.key(), param });
        Ok(())
    }

    // ---------------------------------------------------------------
    // Allowlist — adding is a weakening action (delayed by
    // address_delay); removing is a strengthening action (immediate) and
    // bumps the epoch so any in-flight request against the old epoch is
    // invalidated at confirmation. Mirrors addAllowedAddress/
    // removeAllowedAddress/isAddressActive.
    // ---------------------------------------------------------------

    pub fn add_allowed_address(ctx: Context<AddAllowedAddress>) -> Result<()> {
        let extension = &ctx.accounts.extension;
        require!(!extension.locked, AvelockError::VaultLocked);
        let entry = &mut ctx.accounts.entry;
        if entry.active_at != 0 {
            if !extension.voided_by_lock(entry.lock_epoch_at_add, entry.active_at) {
                return Ok(()); // Already pending/active — matches the EVM no-op.
            }
            // Voided by a lock while it waited: add again, wait again.
            entry.epoch = entry.epoch.checked_add(1).unwrap();
        }
        let now = Clock::get()?.unix_timestamp;
        entry.extension = extension.key();
        entry.destination = ctx.accounts.destination.key();
        entry.active_at = now + extension.address_delay;
        entry.lock_epoch_at_add = extension.lock_epoch;
        entry.bump = ctx.bumps.entry;
        emit!(AddressAdded { extension: entry.extension, destination: entry.destination, active_at: entry.active_at });
        Ok(())
    }

    pub fn remove_allowed_address(ctx: Context<RemoveAllowedAddress>) -> Result<()> {
        let entry = &mut ctx.accounts.entry;
        entry.epoch = entry.epoch.checked_add(1).unwrap();
        entry.active_at = 0;
        emit!(AddressRemoved { extension: entry.extension, destination: entry.destination });
        Ok(())
    }

    // ---------------------------------------------------------------
    // Withdrawal lifecycle: request -> wait -> confirm. Split by asset
    // kind at the instruction level (native SOL vs. an SPL mint, which
    // covers both fungible tokens and NFTs) since the required accounts
    // differ, rather than branching at runtime the way the EVM/TON
    // versions do inside one function.
    // ---------------------------------------------------------------

    pub fn request_native_withdrawal(ctx: Context<RequestWithdrawal>, amount: u64) -> Result<()> {
        require!(amount > 0, AvelockError::ZeroAmount);
        require!(!ctx.accounts.extension.locked, AvelockError::VaultLocked);
        let now = Clock::get()?.unix_timestamp;
        require!(ctx.accounts.allowlist.is_active(&ctx.accounts.extension, now), AvelockError::DestinationNotAllowed);

        let extension = &mut ctx.accounts.extension;
        let request = &mut ctx.accounts.request;
        request.extension = extension.key();
        request.id = extension.next_request_id;
        request.to = ctx.accounts.to.key();
        request.mint = None;
        request.amount = amount;
        request.available_at = now + extension.withdrawal_delay;
        request.expires_at = request.available_at + extension.confirmation_window;
        request.epoch_at_request = ctx.accounts.allowlist.epoch;
        request.lock_epoch_at_request = extension.lock_epoch;
        request.executed = false;
        request.cancelled = false;
        request.bump = ctx.bumps.request;
        extension.next_request_id = extension.next_request_id.checked_add(1).unwrap();

        emit!(WithdrawalRequested {
            extension: request.extension,
            id: request.id,
            to: request.to,
            mint: None,
            amount,
            available_at: request.available_at,
            expires_at: request.expires_at,
        });
        Ok(())
    }

    pub fn request_token_withdrawal(ctx: Context<RequestWithdrawal>, amount: u64) -> Result<()> {
        require!(amount > 0, AvelockError::ZeroAmount);
        require!(!ctx.accounts.extension.locked, AvelockError::VaultLocked);
        let now = Clock::get()?.unix_timestamp;
        require!(ctx.accounts.allowlist.is_active(&ctx.accounts.extension, now), AvelockError::DestinationNotAllowed);
        let mint = ctx.accounts.mint.as_ref().ok_or(AvelockError::AssetMismatch)?;

        let extension = &mut ctx.accounts.extension;
        let request = &mut ctx.accounts.request;
        request.extension = extension.key();
        request.id = extension.next_request_id;
        request.to = ctx.accounts.to.key();
        request.mint = Some(mint.key());
        request.amount = amount;
        request.available_at = now + extension.withdrawal_delay;
        request.expires_at = request.available_at + extension.confirmation_window;
        request.epoch_at_request = ctx.accounts.allowlist.epoch;
        request.lock_epoch_at_request = extension.lock_epoch;
        request.executed = false;
        request.cancelled = false;
        request.bump = ctx.bumps.request;
        extension.next_request_id = extension.next_request_id.checked_add(1).unwrap();

        emit!(WithdrawalRequested {
            extension: request.extension,
            id: request.id,
            to: request.to,
            mint: request.mint,
            amount,
            available_at: request.available_at,
            expires_at: request.expires_at,
        });
        Ok(())
    }

    /// Cancel a pending request at any time before execution.
    pub fn cancel_withdrawal(ctx: Context<CancelWithdrawal>) -> Result<()> {
        let request = &mut ctx.accounts.request;
        require!(!request.executed && !request.cancelled, AvelockError::RequestAlreadyFinal);
        request.cancelled = true;
        emit!(WithdrawalCancelled { extension: request.extension, id: request.id });
        Ok(())
    }

    /// Final confirmation after the timelock has elapsed — a second,
    /// separate owner action; the timelock never auto-executes (see
    /// AvelockSecurityExtension.confirmWithdrawal, threat-model
    /// section 10). Native-SOL path: transfers straight out of the
    /// Vault PDA's own lamport balance.
    pub fn confirm_native_withdrawal(ctx: Context<ConfirmNativeWithdrawal>) -> Result<()> {
        let now = Clock::get()?.unix_timestamp;
        {
            let request = &ctx.accounts.request;
            let extension = &ctx.accounts.extension;
            require!(!extension.locked, AvelockError::VaultLocked);
            require!(!request.executed && !request.cancelled, AvelockError::RequestAlreadyFinal);
            require!(!request.is_annulled(extension), AvelockError::RequestAnnulled);
            require!(now >= request.available_at, AvelockError::RequestNotReady);
            require!(now <= request.expires_at, AvelockError::RequestExpired);
            require!(request.mint.is_none(), AvelockError::NotNativeRequest);
            require!(
                ctx.accounts.allowlist.is_active(extension, now)
                    && ctx.accounts.allowlist.epoch == request.epoch_at_request,
                AvelockError::DestinationNotAllowed
            );
            require_keys_eq!(request.to, ctx.accounts.to.key(), AvelockError::AssetMismatch);
        }

        // The Vault owns data as well as SOL. Preserve its rent deposit so
        // an authorized withdrawal cannot destroy the state needed for SPL assets.
        native_transfer::transfer_lamports(
            &ctx.accounts.vault.to_account_info(),
            &ctx.accounts.to.to_account_info(),
            ctx.accounts.request.amount,
            &Rent::get()?,
        )?;

        let request = &mut ctx.accounts.request;
        request.executed = true;
        emit!(WithdrawalExecuted { extension: request.extension, id: request.id });
        Ok(())
    }

    /// SPL-token path (covers both fungible tokens and NFTs — an NFT is
    /// just a mint with supply 1 / 0 decimals on Solana, so no separate
    /// instruction is needed the way EVM needs requestNFTWithdrawal).
    /// The destination token account is the recipient's own associated
    /// token account for this mint, derived and constraint-checked by
    /// Anchor — there is no arbitrary "which contract receives it"
    /// field, unlike TON's jetton-wallet-address bypass this design
    /// closes structurally rather than by an extra allowlist check.
    pub fn confirm_token_withdrawal(ctx: Context<ConfirmTokenWithdrawal>) -> Result<()> {
        let now = Clock::get()?.unix_timestamp;
        {
            let request = &ctx.accounts.request;
            let extension = &ctx.accounts.extension;
            require!(!extension.locked, AvelockError::VaultLocked);
            require!(!request.executed && !request.cancelled, AvelockError::RequestAlreadyFinal);
            require!(!request.is_annulled(extension), AvelockError::RequestAnnulled);
            require!(now >= request.available_at, AvelockError::RequestNotReady);
            require!(now <= request.expires_at, AvelockError::RequestExpired);
            require!(
                ctx.accounts.allowlist.is_active(extension, now)
                    && ctx.accounts.allowlist.epoch == request.epoch_at_request,
                AvelockError::DestinationNotAllowed
            );
            require_keys_eq!(request.to, ctx.accounts.to.key(), AvelockError::AssetMismatch);
            require!(request.mint == Some(ctx.accounts.mint.key()), AvelockError::AssetMismatch);
        }

        let owner_key = ctx.accounts.vault.owner;
        let bump = ctx.accounts.vault.bump;
        let seeds: &[&[u8]] = &[Vault::SEED_PREFIX, owner_key.as_ref(), &[bump]];
        let signer: &[&[&[u8]]] = &[seeds];

        let amount = ctx.accounts.request.amount;
        let cpi_accounts = Transfer {
            from: ctx.accounts.vault_token_account.to_account_info(),
            to: ctx.accounts.destination_token_account.to_account_info(),
            authority: ctx.accounts.vault.to_account_info(),
        };
        let cpi_ctx = CpiContext::new_with_signer(
            ctx.accounts.token_program.to_account_info(),
            cpi_accounts,
            signer,
        );
        token::transfer(cpi_ctx, amount)?;

        let request = &mut ctx.accounts.request;
        request.executed = true;
        emit!(WithdrawalExecuted { extension: request.extension, id: request.id });
        Ok(())
    }

    /// Close a terminal request's account once it has aged past
    /// REQUEST_RETENTION (immediately for a cancelled one) — rent
    /// lamports return to the owner. See
    /// AvelockSecurityExtension.pruneRequest.
    pub fn prune_request(ctx: Context<PruneRequest>) -> Result<()> {
        let now = Clock::get()?.unix_timestamp;
        let request = &ctx.accounts.request;
        let extension = &ctx.accounts.extension;
        require!(request.is_terminal(now, extension), AvelockError::RequestNotPrunable);
        require!(request.retention_satisfied(now, extension), AvelockError::RequestNotPrunable);
        emit!(RequestPruned { extension: request.extension, id: request.id });
        Ok(())
    }

    // ---------------------------------------------------------------
    // Guard keys (plan B1): up to two stop-only keys. Adding and removing
    // both wait address_delay; a guard cannot stop its own removal.
    // ---------------------------------------------------------------

    pub fn add_guard(ctx: Context<OwnerOnly>, key: Pubkey) -> Result<()> {
        let now = Clock::get()?.unix_timestamp;
        let owner = ctx.accounts.owner.key();
        let extension = &mut ctx.accounts.extension;
        require!(!extension.locked, AvelockError::VaultLocked);
        extension.add_guard(key, &owner, now)?;
        emit!(GuardChanged { extension: extension.key(), key, change: GUARD_ADDED });
        Ok(())
    }

    pub fn remove_guard(ctx: Context<OwnerOnly>, key: Pubkey) -> Result<()> {
        let now = Clock::get()?.unix_timestamp;
        let extension = &mut ctx.accounts.extension;
        extension.remove_guard(&key, now)?;
        emit!(GuardChanged { extension: extension.key(), key, change: GUARD_REMOVAL_QUEUED });
        Ok(())
    }

    pub fn cancel_guard_removal(ctx: Context<OwnerOnly>, key: Pubkey) -> Result<()> {
        let extension = &mut ctx.accounts.extension;
        extension.cancel_guard_removal(&key)?;
        emit!(GuardChanged { extension: extension.key(), key, change: GUARD_REMOVAL_CANCELLED });
        Ok(())
    }

    pub fn finalize_guard_removal(ctx: Context<OwnerOnly>, key: Pubkey) -> Result<()> {
        let now = Clock::get()?.unix_timestamp;
        let extension = &mut ctx.accounts.extension;
        extension.finalize_guard_removal(&key, now)?;
        emit!(GuardChanged { extension: extension.key(), key, change: GUARD_REMOVED });
        Ok(())
    }

    // ---------------------------------------------------------------
    // Panic Lock (plan B2): instant to set (owner or guard), lifted only
    // by the owner after lock_delay.
    // ---------------------------------------------------------------

    pub fn lock(ctx: Context<OwnerOnly>) -> Result<()> {
        let now = Clock::get()?.unix_timestamp;
        let extension = &mut ctx.accounts.extension;
        extension.lock(now);
        emit!(Locked { extension: extension.key(), by: ctx.accounts.owner.key(), unlock_after: extension.unlock_after });
        Ok(())
    }

    pub fn unlock(ctx: Context<OwnerOnly>) -> Result<()> {
        let now = Clock::get()?.unix_timestamp;
        let extension = &mut ctx.accounts.extension;
        extension.unlock(now)?;
        emit!(Unlocked { extension: extension.key() });
        Ok(())
    }

    // Guard actions: the guard signs and pays its own fees.

    pub fn guard_lock(ctx: Context<GuardAction>) -> Result<()> {
        let now = Clock::get()?.unix_timestamp;
        let extension = &mut ctx.accounts.extension;
        require!(extension.is_guard(&ctx.accounts.guard.key(), now), AvelockError::NotGuard);
        extension.lock(now);
        emit!(Locked { extension: extension.key(), by: ctx.accounts.guard.key(), unlock_after: extension.unlock_after });
        Ok(())
    }

    pub fn guard_cancel_param_change(ctx: Context<GuardAction>, param: u8) -> Result<()> {
        let now = Clock::get()?.unix_timestamp;
        let extension = &mut ctx.accounts.extension;
        require!(extension.is_guard(&ctx.accounts.guard.key(), now), AvelockError::NotGuard);
        let idx = param as usize;
        require!(idx < PARAM_COUNT, AvelockError::InvalidParameter);
        require!(extension.pending[idx].exists, AvelockError::NoPendingChange);
        extension.pending[idx] = PendingParamChange::default();
        emit!(ParamChangeCancelled { extension: extension.key(), param });
        Ok(())
    }

    pub fn guard_drop_pending_guard(ctx: Context<GuardAction>, key: Pubkey) -> Result<()> {
        let now = Clock::get()?.unix_timestamp;
        let extension = &mut ctx.accounts.extension;
        require!(extension.is_guard(&ctx.accounts.guard.key(), now), AvelockError::NotGuard);
        extension.drop_pending_guard(&key, now)?;
        emit!(GuardChanged { extension: extension.key(), key, change: GUARD_REMOVED });
        Ok(())
    }

    pub fn guard_cancel_withdrawal(ctx: Context<GuardCancelWithdrawal>) -> Result<()> {
        let now = Clock::get()?.unix_timestamp;
        require!(ctx.accounts.extension.is_guard(&ctx.accounts.guard.key(), now), AvelockError::NotGuard);
        let request = &mut ctx.accounts.request;
        require!(!request.executed && !request.cancelled, AvelockError::RequestAlreadyFinal);
        request.cancelled = true;
        emit!(WithdrawalCancelled { extension: request.extension, id: request.id });
        Ok(())
    }

    pub fn guard_cancel_pending_address(ctx: Context<GuardCancelPendingAddress>) -> Result<()> {
        let now = Clock::get()?.unix_timestamp;
        require!(ctx.accounts.extension.is_guard(&ctx.accounts.guard.key(), now), AvelockError::NotGuard);
        let entry = &mut ctx.accounts.entry;
        require!(entry.active_at != 0 && now < entry.active_at, AvelockError::NotPending);
        entry.epoch = entry.epoch.checked_add(1).unwrap();
        entry.active_at = 0;
        emit!(AddressRemoved { extension: entry.extension, destination: entry.destination });
        Ok(())
    }
}

pub const GUARD_ADDED: u8 = 0;
pub const GUARD_REMOVAL_QUEUED: u8 = 1;
pub const GUARD_REMOVAL_CANCELLED: u8 = 2;
pub const GUARD_REMOVED: u8 = 3;

fn validate_param(param: u8, value: i64) -> Result<()> {
    let limit = if param == PARAM_CONFIRMATION_WINDOW { MAX_CONFIRMATION_WINDOW } else { MAX_DELAY };
    require!(value > 0 && value <= limit, AvelockError::InvalidParameter);
    Ok(())
}

/// Every actual parameter change waits under the *current* policy delay,
/// including increases — mirrors AvelockSecurityExtension._proposeChange.
fn propose_change(extension: &mut Account<SecurityExtension>, param: u8, new_value: i64, current_value: i64) -> Result<()> {
    validate_param(param, new_value)?;
    if new_value == current_value {
        // Withdraws a queued change for this parameter (audit M-1).
        extension.pending[param as usize] = PendingParamChange::default();
        return Ok(());
    }
    let now = Clock::get()?.unix_timestamp;
    let effective_at = now + change_wait(extension.policy_delay, extension.withdrawal_delay);
    extension.pending[param as usize] = PendingParamChange { new_value, effective_at, exists: true };
    emit!(ParamChangeQueued { extension: extension.key(), param, new_value, effective_at });
    Ok(())
}

/// A change waits the policy delay, never less than the withdrawal delay
/// (audit A14-2): else a short policy delay lowers the withdrawal delay and a
/// phrase thief withdraws sooner than the owner's delay.
pub(crate) fn change_wait(policy_delay: i64, withdrawal_delay: i64) -> i64 {
    policy_delay.max(withdrawal_delay)
}

/// The lock delay a change may leave: never below the withdrawal delay.
pub(crate) fn lock_delay_floor(lock_delay: i64, withdrawal_delay: i64) -> i64 {
    lock_delay.max(withdrawal_delay)
}

/// Invariant (audit A12-3): lock_delay >= withdrawal_delay when a change
/// applies, so a lock never lifts sooner than a withdrawal could complete.
fn write_param(extension: &mut Account<SecurityExtension>, param: u8, value: i64) {
    match param {
        PARAM_WITHDRAWAL_DELAY => {
            extension.withdrawal_delay = value;
            extension.lock_delay = lock_delay_floor(extension.lock_delay, value);
        }
        PARAM_ADDRESS_DELAY => extension.address_delay = value,
        PARAM_CONFIRMATION_WINDOW => extension.confirmation_window = value,
        PARAM_LOCK_DELAY => extension.lock_delay = lock_delay_floor(value, extension.withdrawal_delay),
        _ => extension.policy_delay = value,
    }
}

// ============================================================
// Accounts contexts
// ============================================================

#[derive(Accounts)]
pub struct InitializeVault<'info> {
    #[account(mut)]
    pub owner: Signer<'info>,

    #[account(
        init,
        payer = owner,
        space = Vault::SPACE,
        seeds = [Vault::SEED_PREFIX, owner.key().as_ref()],
        bump,
    )]
    pub vault: Account<'info, Vault>,

    #[account(
        init,
        payer = owner,
        space = SecurityExtension::SPACE,
        seeds = [SecurityExtension::SEED_PREFIX, vault.key().as_ref()],
        bump,
    )]
    pub extension: Account<'info, SecurityExtension>,

    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct OwnerOnly<'info> {
    pub owner: Signer<'info>,

    #[account(has_one = owner)]
    pub vault: Account<'info, Vault>,

    #[account(
        mut,
        seeds = [SecurityExtension::SEED_PREFIX, vault.key().as_ref()],
        bump = extension.bump,
        constraint = vault.security_extension == extension.key(),
    )]
    pub extension: Account<'info, SecurityExtension>,
}

#[derive(Accounts)]
pub struct AddAllowedAddress<'info> {
    #[account(mut)]
    pub owner: Signer<'info>,

    #[account(has_one = owner)]
    pub vault: Account<'info, Vault>,

    #[account(
        seeds = [SecurityExtension::SEED_PREFIX, vault.key().as_ref()],
        bump = extension.bump,
    )]
    pub extension: Account<'info, SecurityExtension>,

    /// CHECK: only used as a pure pubkey key for PDA derivation and the
    /// stored `destination` field — never read, written, or CPI'd into.
    pub destination: UncheckedAccount<'info>,

    #[account(
        init_if_needed,
        payer = owner,
        space = AllowlistEntry::SPACE,
        seeds = [AllowlistEntry::SEED_PREFIX, extension.key().as_ref(), destination.key().as_ref()],
        bump,
    )]
    pub entry: Account<'info, AllowlistEntry>,

    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct RemoveAllowedAddress<'info> {
    pub owner: Signer<'info>,

    #[account(has_one = owner)]
    pub vault: Account<'info, Vault>,

    #[account(
        seeds = [SecurityExtension::SEED_PREFIX, vault.key().as_ref()],
        bump = extension.bump,
    )]
    pub extension: Account<'info, SecurityExtension>,

    #[account(
        mut,
        seeds = [AllowlistEntry::SEED_PREFIX, extension.key().as_ref(), entry.destination.as_ref()],
        bump = entry.bump,
    )]
    pub entry: Account<'info, AllowlistEntry>,
}

#[derive(Accounts)]
pub struct RequestWithdrawal<'info> {
    #[account(mut)]
    pub owner: Signer<'info>,

    #[account(has_one = owner)]
    pub vault: Account<'info, Vault>,

    #[account(
        mut,
        seeds = [SecurityExtension::SEED_PREFIX, vault.key().as_ref()],
        bump = extension.bump,
    )]
    pub extension: Account<'info, SecurityExtension>,

    /// CHECK: recipient identity only; see AddAllowedAddress.
    pub to: UncheckedAccount<'info>,

    #[account(
        seeds = [AllowlistEntry::SEED_PREFIX, extension.key().as_ref(), to.key().as_ref()],
        bump = allowlist.bump,
    )]
    pub allowlist: Account<'info, AllowlistEntry>,

    /// Shared by both `request_native_withdrawal` and
    /// `request_token_withdrawal` via Anchor's `Option<Account<..>>`
    /// support (pass `None`/omit for the native-SOL instruction, which
    /// never reads this field). NOT independently verified — check
    /// Anchor's current client-side convention for omitting an Option
    /// account against whatever `anchor-lang` version this ends up
    /// pinned to before relying on it.
    pub mint: Option<Account<'info, Mint>>,

    #[account(
        init,
        payer = owner,
        space = WithdrawalRequest::SPACE,
        seeds = [WithdrawalRequest::SEED_PREFIX, extension.key().as_ref(), &extension.next_request_id.to_le_bytes()],
        bump,
    )]
    pub request: Account<'info, WithdrawalRequest>,

    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct CancelWithdrawal<'info> {
    pub owner: Signer<'info>,

    #[account(has_one = owner)]
    pub vault: Account<'info, Vault>,

    #[account(
        seeds = [SecurityExtension::SEED_PREFIX, vault.key().as_ref()],
        bump = extension.bump,
    )]
    pub extension: Account<'info, SecurityExtension>,

    #[account(
        mut,
        seeds = [WithdrawalRequest::SEED_PREFIX, extension.key().as_ref(), &request.id.to_le_bytes()],
        bump = request.bump,
    )]
    pub request: Account<'info, WithdrawalRequest>,
}

#[derive(Accounts)]
pub struct ConfirmNativeWithdrawal<'info> {
    pub owner: Signer<'info>,

    #[account(mut, has_one = owner)]
    pub vault: Account<'info, Vault>,

    #[account(
        seeds = [SecurityExtension::SEED_PREFIX, vault.key().as_ref()],
        bump = extension.bump,
    )]
    pub extension: Account<'info, SecurityExtension>,

    #[account(
        mut,
        seeds = [WithdrawalRequest::SEED_PREFIX, extension.key().as_ref(), &request.id.to_le_bytes()],
        bump = request.bump,
    )]
    pub request: Account<'info, WithdrawalRequest>,

    #[account(
        seeds = [AllowlistEntry::SEED_PREFIX, extension.key().as_ref(), to.key().as_ref()],
        bump = allowlist.bump,
    )]
    pub allowlist: Account<'info, AllowlistEntry>,

    /// CHECK: lamport recipient; validated against `request.to` in the handler.
    #[account(mut)]
    pub to: UncheckedAccount<'info>,

    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct ConfirmTokenWithdrawal<'info> {
    #[account(mut)]
    pub owner: Signer<'info>,

    #[account(has_one = owner)]
    pub vault: Account<'info, Vault>,

    #[account(
        seeds = [SecurityExtension::SEED_PREFIX, vault.key().as_ref()],
        bump = extension.bump,
    )]
    pub extension: Account<'info, SecurityExtension>,

    #[account(
        mut,
        seeds = [WithdrawalRequest::SEED_PREFIX, extension.key().as_ref(), &request.id.to_le_bytes()],
        bump = request.bump,
    )]
    pub request: Account<'info, WithdrawalRequest>,

    #[account(
        seeds = [AllowlistEntry::SEED_PREFIX, extension.key().as_ref(), to.key().as_ref()],
        bump = allowlist.bump,
    )]
    pub allowlist: Account<'info, AllowlistEntry>,

    /// CHECK: recipient identity only; the actual transfer destination is
    /// `destination_token_account` below, derived from this key.
    pub to: UncheckedAccount<'info>,

    pub mint: Account<'info, Mint>,

    #[account(
        mut,
        associated_token::mint = mint,
        associated_token::authority = vault,
    )]
    pub vault_token_account: Account<'info, TokenAccount>,

    #[account(
        init_if_needed,
        payer = owner,
        associated_token::mint = mint,
        associated_token::authority = to,
    )]
    pub destination_token_account: Box<Account<'info, TokenAccount>>,

    pub token_program: Program<'info, Token>,
    pub associated_token_program: Program<'info, AssociatedToken>,
    pub system_program: Program<'info, System>,
}

/// A guard key acting on the extension (it signs and pays; no owner involved).
#[derive(Accounts)]
pub struct GuardAction<'info> {
    pub guard: Signer<'info>,

    pub vault: Account<'info, Vault>,

    #[account(
        mut,
        seeds = [SecurityExtension::SEED_PREFIX, vault.key().as_ref()],
        bump = extension.bump,
        constraint = vault.security_extension == extension.key(),
    )]
    pub extension: Account<'info, SecurityExtension>,
}

#[derive(Accounts)]
pub struct GuardCancelWithdrawal<'info> {
    pub guard: Signer<'info>,

    pub vault: Account<'info, Vault>,

    #[account(
        seeds = [SecurityExtension::SEED_PREFIX, vault.key().as_ref()],
        bump = extension.bump,
        constraint = vault.security_extension == extension.key(),
    )]
    pub extension: Account<'info, SecurityExtension>,

    #[account(
        mut,
        seeds = [WithdrawalRequest::SEED_PREFIX, extension.key().as_ref(), &request.id.to_le_bytes()],
        bump = request.bump,
    )]
    pub request: Account<'info, WithdrawalRequest>,
}

#[derive(Accounts)]
pub struct GuardCancelPendingAddress<'info> {
    pub guard: Signer<'info>,

    pub vault: Account<'info, Vault>,

    #[account(
        seeds = [SecurityExtension::SEED_PREFIX, vault.key().as_ref()],
        bump = extension.bump,
        constraint = vault.security_extension == extension.key(),
    )]
    pub extension: Account<'info, SecurityExtension>,

    #[account(
        mut,
        seeds = [AllowlistEntry::SEED_PREFIX, extension.key().as_ref(), entry.destination.as_ref()],
        bump = entry.bump,
    )]
    pub entry: Account<'info, AllowlistEntry>,
}

#[derive(Accounts)]
pub struct PruneRequest<'info> {
    #[account(mut)]
    pub owner: Signer<'info>,

    #[account(has_one = owner)]
    pub vault: Account<'info, Vault>,

    #[account(
        seeds = [SecurityExtension::SEED_PREFIX, vault.key().as_ref()],
        bump = extension.bump,
    )]
    pub extension: Account<'info, SecurityExtension>,

    #[account(
        mut,
        close = owner,
        seeds = [WithdrawalRequest::SEED_PREFIX, extension.key().as_ref(), &request.id.to_le_bytes()],
        bump = request.bump,
    )]
    pub request: Account<'info, WithdrawalRequest>,
}

// ============================================================
// Events — mirror the EVM/TON event names where a direct analogue exists.
// ============================================================

#[event]
pub struct VaultInitialized {
    pub vault: Pubkey,
    pub extension: Pubkey,
    pub owner: Pubkey,
}

#[event]
pub struct AddressAdded {
    pub extension: Pubkey,
    pub destination: Pubkey,
    pub active_at: i64,
}

#[event]
pub struct AddressRemoved {
    pub extension: Pubkey,
    pub destination: Pubkey,
}

#[event]
pub struct WithdrawalRequested {
    pub extension: Pubkey,
    pub id: u64,
    pub to: Pubkey,
    pub mint: Option<Pubkey>,
    pub amount: u64,
    pub available_at: i64,
    pub expires_at: i64,
}

#[event]
pub struct WithdrawalCancelled {
    pub extension: Pubkey,
    pub id: u64,
}

#[event]
pub struct WithdrawalExecuted {
    pub extension: Pubkey,
    pub id: u64,
}

#[event]
pub struct ParamChangeQueued {
    pub extension: Pubkey,
    pub param: u8,
    pub new_value: i64,
    pub effective_at: i64,
}

#[event]
pub struct ParamChangeApplied {
    pub extension: Pubkey,
    pub param: u8,
    pub new_value: i64,
}

#[event]
pub struct ParamChangeCancelled {
    pub extension: Pubkey,
    pub param: u8,
}

#[event]
pub struct RequestPruned {
    pub extension: Pubkey,
    pub id: u64,
}

#[event]
pub struct GuardChanged {
    pub extension: Pubkey,
    pub key: Pubkey,
    /// GUARD_ADDED / GUARD_REMOVAL_QUEUED / GUARD_REMOVAL_CANCELLED / GUARD_REMOVED
    pub change: u8,
}

#[event]
pub struct Locked {
    pub extension: Pubkey,
    pub by: Pubkey,
    pub unlock_after: i64,
}

#[event]
pub struct Unlocked {
    pub extension: Pubkey,
}

#[cfg(test)]
mod account_metadata_tests {
    use super::*;

    #[test]
    fn prune_refund_recipient_is_writable_even_with_a_separate_fee_payer() {
        let owner = Pubkey::new_unique();
        // Test generated client metadata, not the hand-written integration helper.
        let metas = crate::accounts::PruneRequest {
            owner,
            vault: Pubkey::new_unique(),
            extension: Pubkey::new_unique(),
            request: Pubkey::new_unique(),
        }.to_account_metas(None);
        let refund = metas.iter().find(|meta| meta.pubkey == owner).unwrap();
        assert!(refund.is_signer);
        assert!(refund.is_writable);
    }
}

#[cfg(test)]
mod lock_delay_tests {
    use super::lock_delay_floor;

    /// Audit A12-3: a lock never lifts sooner than a withdrawal could complete.
    #[test]
    fn lock_delay_never_goes_below_the_withdrawal_delay() {
        let day = 86_400;
        assert_eq!(lock_delay_floor(day, 30 * day), 30 * day); // raising W raises the lock delay
        assert_eq!(lock_delay_floor(10 * day, day), 10 * day); // a longer lock delay stays
    }
}

#[cfg(test)]
mod change_wait_tests {
    use super::change_wait;

    /// Audit A14-2: a short policy delay cannot lower the withdrawal delay
    /// sooner than a withdrawal under it could complete.
    #[test]
    fn a_change_waits_at_least_the_withdrawal_delay() {
        let day = 86_400;
        assert_eq!(change_wait(3_600, 14 * day), 14 * day);
        assert_eq!(change_wait(30 * day, 7 * day), 30 * day);
    }
}
