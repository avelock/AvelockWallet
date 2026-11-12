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
// Localnet integration tests (tests/*.spec.ts) need an SBF build; see README.md.

use anchor_lang::prelude::*;
// Both token programs (round2 M-2): classic SPL Token and Token-2022.
use anchor_spl::token_interface::{self, Mint, TokenAccount, TokenInterface, TransferChecked};
use anchor_spl::token_2022::spl_token_2022::{self, extension::{BaseStateWithExtensions, ExtensionType, StateWithExtensions}};
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
        // A forgotten change does not stay armed forever (round2 L-3).
        require!(now <= pending.effective_at.saturating_add(APPLY_WINDOW), AvelockError::ChangeExpired);

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
        // As the EVM's ZeroAddress (MEGA_AUDIT sol_01 F2).
        require!(ctx.accounts.destination.key() != Pubkey::default(), AvelockError::ZeroAddress);
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

    /// Records that an active destination can no longer be voided by a later
    /// lock (round2 L-4): every later lock comes after `active_at`. Anyone may
    /// call it, also while locked; removal and re-adding reset it.
    pub fn seal_allowed_address(ctx: Context<SealAllowedAddress>) -> Result<()> {
        let now = Clock::get()?.unix_timestamp;
        let entry = &mut ctx.accounts.entry;
        require!(entry.is_active(&ctx.accounts.extension, now), AvelockError::DestinationNotAllowed);
        entry.lock_epoch_at_add = SEALED;
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
    // classic SPL only, see confirm_token_withdrawal) since the required accounts
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
        // Refused here, not after the whole delay: assets this path can never move.
        require_withdrawable_mint(&mint.to_account_info())?;

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
        let now = Clock::get()?.unix_timestamp;
        let request = &mut ctx.accounts.request;
        require!(!request.executed && !request.cancelled, AvelockError::RequestAlreadyFinal);
        // An expired request stays "expired", and its record waits out the
        // retention period (MEGA_AUDIT sol_03 S1).
        require!(now <= request.expires_at, AvelockError::RequestExpired);
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
            // SOL sent to an account of this program or a token account is stranded (round2 L-7).
            let to_owner = *ctx.accounts.to.owner;
            require!(to_owner != crate::ID && to_owner != anchor_spl::token::ID && to_owner != spl_token_2022::ID, AvelockError::InvalidDestination);
            require!(
                ctx.accounts.allowlist.is_active(extension, now)
                    && ctx.accounts.allowlist.epoch == request.epoch_at_request,
                AvelockError::DestinationNotAllowed
            );
            require_keys_eq!(request.to, ctx.accounts.to.key(), AvelockError::DestinationMismatch); // MEGA_AUDIT sol_04 E1
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

    /// Token path for both token programs: classic SPL Token and Token-2022
    /// (round2 M-2), fungible tokens and legacy NFTs (supply 1 / 0 decimals).
    /// Token-2022 mints with a transfer hook or marked non-transferable are
    /// refused at request time; with a transfer fee, the recipient gets the
    /// amount less the issuer's fee. Still stuck: programmable NFTs (frozen
    /// token account), compressed NFTs, Metaplex Core assets, and tokens in a
    /// non-associated account sent to the vault.
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
            require_keys_eq!(request.to, ctx.accounts.to.key(), AvelockError::DestinationMismatch); // MEGA_AUDIT sol_04 E1
            require!(request.mint == Some(ctx.accounts.mint.key()), AvelockError::AssetMismatch);
            // The vault is never its own destination, as on the native path (MEGA_AUDIT sol_01 F5).
            require_keys_neq!(ctx.accounts.to.key(), ctx.accounts.vault.key(), AvelockError::InvalidDestination);
            // Tokens go to a wallet's own token account; one owned by a program
            // (a token account copied as a "deposit address") has no key (round2 L-2).
            require_keys_eq!(*ctx.accounts.to.owner, anchor_lang::system_program::ID, AvelockError::InvalidDestination);
        }

        let owner_key = ctx.accounts.vault.owner;
        let bump = ctx.accounts.vault.bump;
        let seeds: &[&[u8]] = &[Vault::SEED_PREFIX, owner_key.as_ref(), &[bump]];
        let signer: &[&[&[u8]]] = &[seeds];

        let amount = ctx.accounts.request.amount;
        let cpi_accounts = TransferChecked {
            from: ctx.accounts.vault_token_account.to_account_info(),
            mint: ctx.accounts.mint.to_account_info(),
            to: ctx.accounts.destination_token_account.to_account_info(),
            authority: ctx.accounts.vault.to_account_info(),
        };
        let cpi_ctx = CpiContext::new_with_signer(
            ctx.accounts.token_program.to_account_info(),
            cpi_accounts,
            signer,
        );
        // Checked: the mint's decimals are part of the transfer (Token-2022 requires it).
        token_interface::transfer_checked(cpi_ctx, amount, ctx.accounts.mint.decimals)?;

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
    // Guard keys (plan B1): up to two stop-only keys. Adding waits
    // address_delay; removing an active one waits change_wait + lock_delay,
    // also through a lock (MEGA_AUDIT sol_01 F1). A guard cannot stop its own
    // removal.
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
        require!(now <= request.expires_at, AvelockError::RequestExpired); // MEGA_AUDIT sol_03 S1
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
        // Withdraws a queued change for this parameter (audit M-1), with an
        // event as on EVM (MEGA_AUDIT sol_01 F4).
        if extension.pending[param as usize].exists {
            extension.pending[param as usize] = PendingParamChange::default();
            emit!(ParamChangeCancelled { extension: extension.key(), param });
        }
        return Ok(());
    }
    let now = Clock::get()?.unix_timestamp;
    let effective_at = now + change_wait_for(param, new_value, current_value, extension.policy_delay, extension.withdrawal_delay);
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

/// Lowering the address delay costs at least the current address delay
/// (round2 M-1): else a short policy delay lets a phrase thief pay a new
/// address sooner than the owner's address delay.
pub(crate) fn change_wait_for(param: u8, new_value: i64, current_value: i64, policy_delay: i64, withdrawal_delay: i64) -> i64 {
    let wait = change_wait(policy_delay, withdrawal_delay);
    if param == PARAM_ADDRESS_DELAY && new_value < current_value { wait.max(current_value) } else { wait }
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
pub struct SealAllowedAddress<'info> {
    #[account(
        seeds = [SecurityExtension::SEED_PREFIX, extension.wallet.as_ref()],
        bump = extension.bump,
    )]
    pub extension: Account<'info, SecurityExtension>,

    #[account(
        mut,
        has_one = extension,
        seeds = [AllowlistEntry::SEED_PREFIX, extension.key().as_ref(), entry.destination.as_ref()],
        bump = entry.bump,
    )]
    pub entry: Account<'info, AllowlistEntry>,
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
    pub mint: Option<InterfaceAccount<'info, Mint>>,

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

    #[account(mint::token_program = token_program)]
    pub mint: Box<InterfaceAccount<'info, Mint>>,

    #[account(
        mut,
        associated_token::mint = mint,
        associated_token::authority = vault,
        associated_token::token_program = token_program,
    )]
    pub vault_token_account: Box<InterfaceAccount<'info, TokenAccount>>,

    #[account(
        init_if_needed,
        payer = owner,
        associated_token::mint = mint,
        associated_token::authority = to,
        associated_token::token_program = token_program,
    )]
    pub destination_token_account: Box<InterfaceAccount<'info, TokenAccount>>,

    /// The mint's own token program: classic SPL Token or Token-2022.
    pub token_program: Interface<'info, TokenInterface>,
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
    use super::{change_wait, change_wait_for};
    use crate::state::{PARAM_ADDRESS_DELAY, PARAM_WITHDRAWAL_DELAY};

    /// Round2 M-1: lowering the address delay waits at least the old one.
    #[test]
    fn lowering_the_address_delay_waits_the_old_delay() {
        let day = 86_400;
        assert_eq!(change_wait_for(PARAM_ADDRESS_DELAY, day, 30 * day, 7 * day, day), 30 * day);
        assert_eq!(change_wait_for(PARAM_ADDRESS_DELAY, 40 * day, 30 * day, 7 * day, day), 7 * day);
        assert_eq!(change_wait_for(PARAM_WITHDRAWAL_DELAY, day, 30 * day, 7 * day, 2 * day), 7 * day);
    }

    /// Audit A14-2: a short policy delay cannot lower the withdrawal delay
    /// sooner than a withdrawal under it could complete.
    #[test]
    fn a_change_waits_at_least_the_withdrawal_delay() {
        let day = 86_400;
        assert_eq!(change_wait(3_600, 14 * day), 14 * day);
        assert_eq!(change_wait(30 * day, 7 * day), 30 * day);
    }
}

/// A mint this program can move out of the vault (round2 M-2). Classic SPL
/// mints always; Token-2022 mints unless a transfer hook (needs accounts this
/// path does not pass, and the issuer's program decides) or non-transferable.
fn require_withdrawable_mint(mint: &AccountInfo) -> Result<()> {
    if *mint.owner == anchor_spl::token::ID {
        return Ok(());
    }
    require_keys_eq!(*mint.owner, spl_token_2022::ID, AvelockError::UnsupportedAsset);
    let data = mint.try_borrow_data()?;
    let state = StateWithExtensions::<spl_token_2022::state::Mint>::unpack(&data).map_err(|_| error!(AvelockError::UnsupportedAsset))?;
    let types = state.get_extension_types().map_err(|_| error!(AvelockError::UnsupportedAsset))?;
    for t in types {
        require!(
            !matches!(t, ExtensionType::TransferHook | ExtensionType::NonTransferable),
            AvelockError::UnsupportedAsset
        );
    }
    Ok(())
}
