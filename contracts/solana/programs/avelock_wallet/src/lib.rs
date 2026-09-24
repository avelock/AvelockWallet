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
        require!(new_value >= extension.min_withdrawal_delay, AvelockError::BelowImmutableMinimum);
        propose_change(extension, PARAM_WITHDRAWAL_DELAY, new_value, extension.withdrawal_delay)
    }

    pub fn set_address_delay(ctx: Context<OwnerOnly>, new_value: i64) -> Result<()> {
        let extension = &mut ctx.accounts.extension;
        require!(new_value >= extension.min_address_delay, AvelockError::BelowImmutableMinimum);
        propose_change(extension, PARAM_ADDRESS_DELAY, new_value, extension.address_delay)
    }

    pub fn set_confirmation_window(ctx: Context<OwnerOnly>, new_value: i64) -> Result<()> {
        let extension = &mut ctx.accounts.extension;
        propose_change(extension, PARAM_CONFIRMATION_WINDOW, new_value, extension.confirmation_window)
    }

    pub fn set_policy_delay(ctx: Context<OwnerOnly>, new_value: i64) -> Result<()> {
        let extension = &mut ctx.accounts.extension;
        propose_change(extension, PARAM_POLICY_DELAY, new_value, extension.policy_delay)
    }

    /// Finalize a queued parameter change once its effective time has passed.
    pub fn apply_param_change(ctx: Context<OwnerOnly>, param: u8) -> Result<()> {
        let extension = &mut ctx.accounts.extension;
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
        let entry = &mut ctx.accounts.entry;
        if entry.active_at != 0 {
            return Ok(()); // Already pending/active — matches the EVM no-op.
        }
        let now = Clock::get()?.unix_timestamp;
        entry.extension = ctx.accounts.extension.key();
        entry.destination = ctx.accounts.destination.key();
        entry.active_at = now + ctx.accounts.extension.address_delay;
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
        let now = Clock::get()?.unix_timestamp;
        require!(ctx.accounts.allowlist.is_active(now), AvelockError::DestinationNotAllowed);

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
        let now = Clock::get()?.unix_timestamp;
        require!(ctx.accounts.allowlist.is_active(now), AvelockError::DestinationNotAllowed);
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
            require!(!request.executed && !request.cancelled, AvelockError::RequestAlreadyFinal);
            require!(now >= request.available_at, AvelockError::RequestNotReady);
            require!(now <= request.expires_at, AvelockError::RequestExpired);
            require!(request.mint.is_none(), AvelockError::NotNativeRequest);
            require!(
                ctx.accounts.allowlist.is_active(now)
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
            require!(!request.executed && !request.cancelled, AvelockError::RequestAlreadyFinal);
            require!(now >= request.available_at, AvelockError::RequestNotReady);
            require!(now <= request.expires_at, AvelockError::RequestExpired);
            require!(
                ctx.accounts.allowlist.is_active(now)
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
        require!(request.is_terminal(now), AvelockError::RequestNotPrunable);
        require!(request.retention_satisfied(now), AvelockError::RequestNotPrunable);
        emit!(RequestPruned { extension: request.extension, id: request.id });
        Ok(())
    }
}

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
        return Ok(());
    }
    let now = Clock::get()?.unix_timestamp;
    let effective_at = now + extension.policy_delay;
    extension.pending[param as usize] = PendingParamChange { new_value, effective_at, exists: true };
    emit!(ParamChangeQueued { extension: extension.key(), param, new_value, effective_at });
    Ok(())
}

fn write_param(extension: &mut Account<SecurityExtension>, param: u8, value: i64) {
    match param {
        PARAM_WITHDRAWAL_DELAY => extension.withdrawal_delay = value,
        PARAM_ADDRESS_DELAY => extension.address_delay = value,
        PARAM_CONFIRMATION_WINDOW => extension.confirmation_window = value,
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
