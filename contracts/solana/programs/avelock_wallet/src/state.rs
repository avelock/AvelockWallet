use anchor_lang::prelude::*;

use crate::errors::AvelockError;

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
pub const PARAM_LOCK_DELAY: u8 = 4;
pub const PARAM_COUNT: usize = 5;

/// Guard keys and Panic Lock (FEATURE_PLANS.md, B1/B2).
pub const MAX_GUARDS: usize = 2;
/// Default wait before the owner can lift a lock (at least the withdrawal delay).
pub const DEFAULT_LOCK_DELAY: i64 = 7 * 24 * 60 * 60;
/// Lock times kept to decide whether a destination was still waiting when a
/// lock came. Older than this and the destination counts as voided (it must
/// be added again) — the safe side of not knowing.
pub const LOCK_HISTORY: usize = 4;

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

    /// All parameter changes wait the *current* policy delay and
    /// obey the fixed caps above, including increases — see
    /// `_proposeChange` on the EVM side. Indexed by PARAM_* above.
    pub pending: [PendingParamChange; PARAM_COUNT],

    pub bump: u8,

    /// Stop-only second keys: cancel and lock, nothing else.
    pub guards: [GuardSlot; MAX_GUARDS],
    pub lock_delay: i64,
    pub locked: bool,
    pub unlock_after: i64,
    /// Bumped by every lock; requests and waiting destinations from before
    /// a lock can no longer be used.
    pub lock_epoch: u64,
    /// `lock_times[(e - 1) % LOCK_HISTORY]` is when lock epoch `e` began.
    pub lock_times: [i64; LOCK_HISTORY],
}

impl SecurityExtension {
    pub const SEED_PREFIX: &'static [u8] = b"avelock-extension";
    pub const SPACE: usize = 8 // discriminator
        + 32 // wallet
        + 8 * 6 // the six delay/minimum fields
        + 8 // next_request_id
        + PendingParamChange::SPACE * PARAM_COUNT
        + 1 // bump
        + GuardSlot::SPACE * MAX_GUARDS
        + 8 // lock_delay
        + 1 // locked
        + 8 // unlock_after
        + 8 // lock_epoch
        + 8 * LOCK_HISTORY; // lock_times

    pub fn guard_index(&self, key: &Pubkey) -> Option<usize> {
        if *key == Pubkey::default() {
            return None;
        }
        self.guards.iter().position(|g| g.key == *key)
    }

    /// An added guard is active once its wait is over (and until removed).
    pub fn is_guard(&self, key: &Pubkey, now: i64) -> bool {
        self.guard_index(key).map_or(false, |i| now >= self.guards[i].active_at)
    }

    pub fn add_guard(&mut self, key: Pubkey, owner: &Pubkey, now: i64) -> Result<()> {
        require!(key != Pubkey::default() && key != *owner, AvelockError::InvalidParameter);
        require!(self.guard_index(&key).is_none(), AvelockError::GuardExists);
        let free = self.guards.iter().position(|g| g.key == Pubkey::default()).ok_or(AvelockError::TooManyGuards)?;
        self.guards[free] = GuardSlot { key, active_at: now + self.address_delay, removable_at: 0 };
        Ok(())
    }

    /// A guard still waiting is dropped at once; an active one is queued for
    /// removal and stays active for `address_delay`.
    pub fn remove_guard(&mut self, key: &Pubkey, now: i64) -> Result<()> {
        let i = self.guard_index(key).ok_or(AvelockError::GuardNotFound)?;
        let address_delay = self.address_delay;
        let g = &mut self.guards[i];
        if now < g.active_at {
            *g = GuardSlot::default();
        } else if g.removable_at == 0 {
            // Queued only while unlocked; a lock drops it (audit A15-1).
            require!(!self.locked, AvelockError::VaultLocked);
            self.guards[i].removable_at = now + address_delay;
        }
        Ok(())
    }

    /// Drops a guard that is still waiting (used by guards: stop-only).
    pub fn drop_pending_guard(&mut self, key: &Pubkey, now: i64) -> Result<()> {
        let i = self.guard_index(key).ok_or(AvelockError::GuardNotFound)?;
        require!(now < self.guards[i].active_at, AvelockError::NotPending);
        self.guards[i] = GuardSlot::default();
        Ok(())
    }

    pub fn cancel_guard_removal(&mut self, key: &Pubkey) -> Result<()> {
        let i = self.guard_index(key).ok_or(AvelockError::GuardNotFound)?;
        require!(self.guards[i].removable_at != 0, AvelockError::NotPending);
        self.guards[i].removable_at = 0;
        Ok(())
    }

    pub fn finalize_guard_removal(&mut self, key: &Pubkey, now: i64) -> Result<()> {
        let i = self.guard_index(key).ok_or(AvelockError::GuardNotFound)?;
        let at = self.guards[i].removable_at;
        require!(at != 0, AvelockError::NotPending);
        require!(now >= at, AvelockError::ChangeNotReady);
        // Never during a lock (audit A15-1): else a phrase thief waits out
        // the guard's lock and no one is left to extend it.
        require!(!self.locked, AvelockError::VaultLocked);
        self.guards[i] = GuardSlot::default();
        Ok(())
    }

    /// Panic Lock: instant. Voids pending requests and waiting destinations
    /// (by epoch), cancels queued changes, waiting guards and queued guard
    /// removals. Locking again
    /// extends the wait.
    pub fn lock(&mut self, now: i64) {
        let until = now + self.lock_delay;
        if self.locked {
            self.unlock_after = self.unlock_after.max(until);
            return;
        }
        self.locked = true;
        self.unlock_after = until;
        self.lock_epoch += 1;
        self.lock_times[((self.lock_epoch - 1) % LOCK_HISTORY as u64) as usize] = now;
        self.pending = [PendingParamChange::default(); PARAM_COUNT];
        for g in self.guards.iter_mut() {
            if g.key != Pubkey::default() && now < g.active_at {
                *g = GuardSlot::default();
            } else {
                // A queued removal of an active guard is void too (A15-1).
                g.removable_at = 0;
            }
        }
    }

    /// Only the owner unlocks, and only after `unlock_after`.
    pub fn unlock(&mut self, now: i64) -> Result<()> {
        require!(self.locked, AvelockError::NotLocked);
        require!(now >= self.unlock_after, AvelockError::LockNotExpired);
        self.locked = false;
        Ok(())
    }

    /// True when the first lock after `added_epoch` came before `active_at`
    /// (the destination was still waiting), or is too old to know.
    pub fn voided_by_lock(&self, added_epoch: u64, active_at: i64) -> bool {
        if self.lock_epoch <= added_epoch {
            return false;
        }
        let first = added_epoch + 1;
        if self.lock_epoch - first >= LOCK_HISTORY as u64 {
            return true;
        }
        self.lock_times[((first - 1) % LOCK_HISTORY as u64) as usize] < active_at
    }
}

#[derive(AnchorSerialize, AnchorDeserialize, Clone, Copy, Default, PartialEq, Debug)]
pub struct GuardSlot {
    /// Pubkey::default() = empty slot.
    pub key: Pubkey,
    pub active_at: i64,
    /// 0 = no removal queued.
    pub removable_at: i64,
}

impl GuardSlot {
    pub const SPACE: usize = 32 + 8 + 8;
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
    /// The extension's lock epoch when this destination was added.
    pub lock_epoch_at_add: u64,
}

impl AllowlistEntry {
    pub const SEED_PREFIX: &'static [u8] = b"avelock-allowlist";
    pub const SPACE: usize = 8 + 32 + 32 + 8 + 8 + 1 + 8;

    /// Usable: past its wait, and not voided by a lock that came while it waited.
    pub fn is_active(&self, extension: &SecurityExtension, now: i64) -> bool {
        self.active_at != 0 && now >= self.active_at && !extension.voided_by_lock(self.lock_epoch_at_add, self.active_at)
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
    /// Must still equal the extension's lock epoch at confirmation.
    pub lock_epoch_at_request: u64,
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
        + 1 // bump
        + 8; // lock_epoch_at_request

    pub fn is_terminal(&self, now: i64, extension: &SecurityExtension) -> bool {
        self.executed || self.cancelled || self.is_annulled(extension) || now > self.expires_at
    }

    /// Voided by a lock after it was made.
    pub fn is_annulled(&self, extension: &SecurityExtension) -> bool {
        !self.executed && self.lock_epoch_at_request != extension.lock_epoch
    }

    /// A cancelled request never moved anything and may be pruned
    /// immediately. An executed (settled) or expired-unconfirmed one
    /// waits out `REQUEST_RETENTION` first, so a completed withdrawal's
    /// record stays available for audit for a while — see
    /// AvelockSecurityExtension.pruneRequest.
    pub fn retention_satisfied(&self, now: i64, extension: &SecurityExtension) -> bool {
        self.cancelled || self.is_annulled(extension) || now > self.expires_at + REQUEST_RETENTION
    }
}

#[cfg(test)]
mod guard_lock_tests {
    use super::*;

    const DAY: i64 = 24 * 60 * 60;

    fn extension() -> SecurityExtension {
        SecurityExtension {
            wallet: Pubkey::new_unique(),
            withdrawal_delay: DAY,
            address_delay: 2 * DAY,
            confirmation_window: DAY,
            policy_delay: 3 * DAY,
            min_withdrawal_delay: DAY,
            min_address_delay: DAY,
            next_request_id: 0,
            pending: [PendingParamChange::default(); PARAM_COUNT],
            bump: 0,
            guards: [GuardSlot::default(); MAX_GUARDS],
            lock_delay: DEFAULT_LOCK_DELAY,
            locked: false,
            unlock_after: 0,
            lock_epoch: 0,
            lock_times: [0; LOCK_HISTORY],
        }
    }

    fn entry(ext: &SecurityExtension, active_at: i64) -> AllowlistEntry {
        AllowlistEntry { extension: Pubkey::new_unique(), destination: Pubkey::new_unique(), active_at, epoch: 0, bump: 0, lock_epoch_at_add: ext.lock_epoch }
    }

    #[test]
    fn a_guard_waits_the_address_delay_and_there_are_at_most_two() {
        let owner = Pubkey::new_unique();
        let (a, b, c) = (Pubkey::new_unique(), Pubkey::new_unique(), Pubkey::new_unique());
        let mut ext = extension();
        ext.add_guard(a, &owner, 100).unwrap();
        assert!(!ext.is_guard(&a, 100 + DAY));
        assert!(ext.is_guard(&a, 100 + 2 * DAY));
        assert!(ext.add_guard(a, &owner, 100).is_err()); // duplicate
        assert!(ext.add_guard(owner, &owner, 100).is_err()); // the owner itself
        ext.add_guard(b, &owner, 100).unwrap();
        assert!(ext.add_guard(c, &owner, 100).is_err()); // a third
    }

    /// A15-1: a queued removal of the guard cannot finish during a lock, the
    /// lock drops it, and a new one cannot be queued while locked.
    #[test]
    fn a_lock_drops_a_queued_guard_removal_and_it_cannot_finish_while_locked() {
        let owner = Pubkey::new_unique();
        let g = Pubkey::new_unique();
        let mut ext = extension();
        ext.add_guard(g, &owner, 0).unwrap();
        let t = 3 * DAY;
        ext.remove_guard(&g, t).unwrap();
        ext.lock(t + 1);
        assert!(ext.finalize_guard_removal(&g, t + 3 * DAY).is_err());
        assert!(ext.remove_guard(&g, t + 3 * DAY).is_err());
        let later = t + 30 * DAY;
        ext.unlock(later).unwrap();
        assert!(ext.finalize_guard_removal(&g, later).is_err()); // dropped by the lock
        assert!(ext.is_guard(&g, later));
    }

    #[test]
    fn removing_an_active_guard_waits_while_a_waiting_one_goes_at_once() {
        let owner = Pubkey::new_unique();
        let (a, b) = (Pubkey::new_unique(), Pubkey::new_unique());
        let mut ext = extension();
        ext.add_guard(a, &owner, 0).unwrap();
        ext.remove_guard(&a, 3 * DAY).unwrap();
        assert!(ext.is_guard(&a, 3 * DAY)); // still active while queued
        assert!(ext.finalize_guard_removal(&a, 4 * DAY).is_err());
        ext.finalize_guard_removal(&a, 5 * DAY).unwrap();
        assert!(!ext.is_guard(&a, 5 * DAY));

        ext.add_guard(b, &owner, 10 * DAY).unwrap();
        ext.remove_guard(&b, 10 * DAY).unwrap();
        assert!(ext.guard_index(&b).is_none());
    }

    #[test]
    fn a_guard_may_drop_only_a_waiting_guard() {
        let owner = Pubkey::new_unique();
        let (a, b) = (Pubkey::new_unique(), Pubkey::new_unique());
        let mut ext = extension();
        ext.add_guard(a, &owner, 0).unwrap();
        ext.add_guard(b, &owner, 3 * DAY).unwrap();
        assert!(ext.drop_pending_guard(&a, 3 * DAY).is_err()); // active
        ext.drop_pending_guard(&b, 3 * DAY).unwrap();
        assert!(ext.guard_index(&b).is_none());
    }

    #[test]
    fn lock_cancels_queued_changes_and_waiting_guards_and_extends_when_repeated() {
        let owner = Pubkey::new_unique();
        let (a, b) = (Pubkey::new_unique(), Pubkey::new_unique());
        let mut ext = extension();
        ext.add_guard(a, &owner, 0).unwrap();
        ext.add_guard(b, &owner, 5 * DAY).unwrap();
        ext.pending[PARAM_POLICY_DELAY as usize] = PendingParamChange { new_value: DAY, effective_at: 9 * DAY, exists: true };
        ext.lock(5 * DAY);
        assert!(ext.locked);
        assert_eq!(ext.unlock_after, 5 * DAY + DEFAULT_LOCK_DELAY);
        assert!(!ext.pending[PARAM_POLICY_DELAY as usize].exists);
        assert!(ext.guard_index(&b).is_none());
        assert!(ext.is_guard(&a, 5 * DAY));
        ext.lock(8 * DAY);
        assert_eq!(ext.unlock_after, 8 * DAY + DEFAULT_LOCK_DELAY);
        assert_eq!(ext.lock_epoch, 1);
    }

    #[test]
    fn unlock_only_after_the_lock_delay() {
        let mut ext = extension();
        assert!(ext.unlock(0).is_err()); // not locked
        ext.lock(0);
        assert!(ext.unlock(DEFAULT_LOCK_DELAY - 1).is_err());
        ext.unlock(DEFAULT_LOCK_DELAY).unwrap();
        assert!(!ext.locked);
    }

    #[test]
    fn a_lock_voids_requests_and_waiting_destinations_but_not_active_ones() {
        let mut ext = extension();
        let active = entry(&ext, 10);
        let waiting = entry(&ext, 50);
        let request = WithdrawalRequest {
            extension: Pubkey::new_unique(), id: 0, to: Pubkey::new_unique(), mint: None, amount: 1,
            available_at: 30, expires_at: 40, epoch_at_request: 0, executed: false, cancelled: false, bump: 0,
            lock_epoch_at_request: ext.lock_epoch,
        };
        ext.lock(20);
        assert!(request.is_annulled(&ext));
        assert!(request.is_terminal(20, &ext) && request.retention_satisfied(20, &ext));
        assert!(active.is_active(&ext, 60));
        assert!(!waiting.is_active(&ext, 60));
        ext.unlock(20 + DEFAULT_LOCK_DELAY).unwrap();
        assert!(!waiting.is_active(&ext, 20 + DEFAULT_LOCK_DELAY));
        // Added after the lock: unaffected by it.
        let fresh = entry(&ext, 30 + DEFAULT_LOCK_DELAY);
        assert!(fresh.is_active(&ext, 30 + DEFAULT_LOCK_DELAY));
    }

    #[test]
    fn a_destination_from_before_the_kept_lock_history_counts_as_voided() {
        let mut ext = extension();
        let old = entry(&ext, 10);
        for i in 0..LOCK_HISTORY as i64 {
            let t = 100 + i * 2 * DEFAULT_LOCK_DELAY;
            ext.lock(t);
            ext.unlock(t + DEFAULT_LOCK_DELAY).unwrap();
        }
        // Still within the kept history: the first lock came after it was active.
        assert!(old.is_active(&ext, 10_000_000));
        ext.lock(10_000_000);
        // One lock too many: we no longer know, so it must be added again.
        assert!(!old.is_active(&ext, 10_000_001));
    }
}
