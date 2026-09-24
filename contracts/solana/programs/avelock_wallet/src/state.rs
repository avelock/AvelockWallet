use anchor_lang::prelude::*;

// ============================================================
// Avelock Wallet — Solana port
// Self-custody vault with on-chain withdrawal delays.
// https://github.com/avelock/AvelockWallet
// ============================================================
//
// Mirrors the EVM/TON AvelockWallet + AvelockSecurityExtension pair.
// Solana has no analogue of "deploy a second contract and permanently
// bind it" — a program's accounts are all owned by the one program from
// the start — so the split here is conceptual rather than physical:
// `Vault` mirrors AvelockWallet (owner, and which module accounts are
// trusted to move funds), `SecurityExtension` mirrors
// AvelockSecurityExtension (delays, allowlist, request lifecycle). Both
// are created atomically by `initialize_vault`, so there is no bootstrap
// window on this chain either.
//
// The EVM/TON "no owner-execution bypass" property is structural here
// rather than something the code has to actively refuse: this program
// simply never defines an instruction that moves the Vault's lamports or
// SPL tokens outside of `confirm_native_withdrawal` /
// `confirm_token_withdrawal`, both of which enforce the full
// request -> delay -> confirm lifecycle. There is no `execute`/
// `executeAsOwner` equivalent to disable, because it was never written.

/// Withdrawal/address/policy delay cap — see AvelockSecurityExtension.MAX_DELAY.
pub const MAX_DELAY: i64 = 90 * 24 * 60 * 60; // 90 days
/// Confirmation window cap — see AvelockSecurityExtension.MAX_CONFIRMATION_WINDOW.
pub const MAX_CONFIRMATION_WINDOW: i64 = 30 * 24 * 60 * 60; // 30 days
/// How long a terminal request is kept before its account can be closed —
/// see AvelockSecurityExtension.REQUEST_RETENTION. Closing early returns
/// its rent-exempt lamports to the owner, the Solana analogue of an EVM
/// storage refund.
pub const REQUEST_RETENTION: i64 = 182 * 24 * 60 * 60; // 182 days

pub const PARAM_WITHDRAWAL_DELAY: u8 = 0;
pub const PARAM_ADDRESS_DELAY: u8 = 1;
pub const PARAM_CONFIRMATION_WINDOW: u8 = 2;
pub const PARAM_POLICY_DELAY: u8 = 3;
pub const PARAM_COUNT: usize = 4;

/// Mirrors AvelockWallet: owner + the one module account trusted to move funds.
#[account]
pub struct Vault {
    /// Set once at `initialize_vault` and never changed by any
    /// instruction in this program — the Solana equivalent of EVM's
    /// `immutable owner`. Rotation was deliberately removed on EVM/TON
    /// too: a delayed owner-chosen replacement key does not defend
    /// against a stolen seed, since the attacker holds the same key and
    /// can rotate first. See RECOVERY_DESIGN.md for what a real fix needs.
    pub owner: Pubkey,
    /// The one `SecurityExtension` account permanently trusted to
    /// authorize spends from this vault. Set once, alongside `owner`, in
    /// the same instruction that creates this account — no separate
    /// bootstrap step exists.
    pub security_extension: Pubkey,
    pub bump: u8,
}

impl Vault {
    pub const SEED_PREFIX: &'static [u8] = b"avelock-vault";
    pub const SPACE: usize = 8 // discriminator
        + 32 // owner
        + 32 // security_extension
        + 1; // bump
}

/// Mirrors AvelockSecurityExtension's scalar config. Per-destination and
/// per-request state live in their own PDA accounts below — Solana has
/// no on-account mapping type, so each `mapping(...) =>` from the EVM
/// contract becomes its own account type here.
#[account]
pub struct SecurityExtension {
    pub wallet: Pubkey,

    pub withdrawal_delay: i64,
    pub address_delay: i64,
    pub confirmation_window: i64,
    pub policy_delay: i64,

    /// Permanent floors set once at creation. No instruction in this
    /// program can ever change them, at any delay — see
    /// AvelockSecurityExtension's "Immutable Minimum" (threat-model
    /// section 14). A Vault meant to hold funds for years should set
    /// these deliberately high at creation.
    pub min_withdrawal_delay: i64,
    pub min_address_delay: i64,

    pub next_request_id: u64,

    /// All four parameter changes wait the *current* policy delay and
    /// obey the fixed caps above, including increases — see
    /// `_proposeChange` on the EVM side. Indexed by PARAM_* above.
    pub pending: [PendingParamChange; PARAM_COUNT],

    pub bump: u8,
}

impl SecurityExtension {
    pub const SEED_PREFIX: &'static [u8] = b"avelock-extension";
    pub const SPACE: usize = 8 // discriminator
        + 32 // wallet
        + 8 * 6 // the six delay/minimum fields
        + 8 // next_request_id
        + PendingParamChange::SPACE * PARAM_COUNT
        + 1; // bump
}

#[derive(AnchorSerialize, AnchorDeserialize, Clone, Copy, Default)]
pub struct PendingParamChange {
    pub new_value: i64,
    pub effective_at: i64,
    pub exists: bool,
}

impl PendingParamChange {
    pub const SPACE: usize = 8 + 8 + 1;
}

/// Mirrors `allowlistActiveAt`/`allowlistEpoch`. Adding a new destination
/// is a weakening action (delayed by `address_delay`); removing one is a
/// strengthening action (immediate) and bumps `epoch` so any withdrawal
/// request already in flight against the old epoch is invalidated at
/// confirmation — see AvelockSecurityExtension's revocation-epoch check.
#[account]
pub struct AllowlistEntry {
    pub extension: Pubkey,
    pub destination: Pubkey,
    /// 0 = never added (or fully removed and not re-added).
    pub active_at: i64,
    pub epoch: u64,
    pub bump: u8,
}

impl AllowlistEntry {
    pub const SEED_PREFIX: &'static [u8] = b"avelock-allowlist";
    pub const SPACE: usize = 8 + 32 + 32 + 8 + 8 + 1;

    pub fn is_active(&self, now: i64) -> bool {
        self.active_at != 0 && now >= self.active_at
    }
}

/// Mirrors `WithdrawalRequest`/`requestEpoch`/`assetKind`/`tokenId`. On
/// Solana a fungible token and an NFT are both just SPL mints (an NFT is
/// simply a mint with supply 1 and 0 decimals), so — unlike the EVM side,
/// which needs a separate `requestNFTWithdrawal` and an
/// ERC-20/721/1155 discriminant — one `mint: Option<Pubkey>` field
/// covers native SOL (`None`) and any SPL asset (`Some`) uniformly.
#[account]
pub struct WithdrawalRequest {
    pub extension: Pubkey,
    pub id: u64,
    pub to: Pubkey,
    /// `None` = native SOL. `Some(mint)` = an SPL token or NFT mint;
    /// the actual transfer destination is `to`'s associated token
    /// account for this mint, which `confirm_token_withdrawal`'s account
    /// constraints derive and check deterministically — there is no
    /// arbitrary-destination-account field to redirect, unlike TON's
    /// jetton-wallet-address bypass this design already closes.
    pub mint: Option<Pubkey>,
    pub amount: u64,
    pub available_at: i64,
    pub expires_at: i64,
    /// Snapshot of the destination's allowlist epoch at request time —
    /// re-checked against the *current* epoch at confirmation, so
    /// removing (and possibly re-adding) `to` invalidates this request.
    pub epoch_at_request: u64,
    pub executed: bool,
    pub cancelled: bool,
    pub bump: u8,
}

impl WithdrawalRequest {
    pub const SEED_PREFIX: &'static [u8] = b"avelock-request";
    pub const SPACE: usize = 8 // discriminator
        + 32 // extension
        + 8 // id
        + 32 // to
        + (1 + 32) // mint: Option<Pubkey>
        + 8 // amount
        + 8 // available_at
        + 8 // expires_at
        + 8 // epoch_at_request
        + 1 // executed
        + 1 // cancelled
        + 1; // bump

    pub fn is_terminal(&self, now: i64) -> bool {
        self.executed || self.cancelled || now > self.expires_at
    }

    /// A cancelled request never moved anything and may be pruned
    /// immediately. An executed (settled) or expired-unconfirmed one
    /// waits out `REQUEST_RETENTION` first, so a completed withdrawal's
    /// record stays available for audit for a while — see
    /// AvelockSecurityExtension.pruneRequest.
    pub fn retention_satisfied(&self, now: i64) -> bool {
        self.cancelled || now > self.expires_at + REQUEST_RETENTION
    }
}
