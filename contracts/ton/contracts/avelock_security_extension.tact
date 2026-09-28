asm fun chainGlobalId(): Int { GLOBALID }
// ============================================================
// Avelock Wallet — Security Extension
// Self-custody vault with on-chain withdrawal delays.
// https://github.com/avelock/AvelockWallet
// ============================================================
//
// AvelockSecurityExtension — TON port of the EVM AvelockSecurityExtension.
// Same state machine: request -> delay -> confirm -> execute withdrawals,
// an address allowlist with its own activation delay, a Security Policy
// Delay gating any weakening parameter change, and immutable minimums
// that no owner action can ever go below.
//
// Unlike the EVM version (where the extension is msg.sender-checked
// against the wallet's owner), this contract has its OWN owner public key
// and its OWN seqno — TON has no notion of an EOA calling a contract
// directly, so every owner action here goes through the same
// signed-external-message pattern as AvelockWallet itself. Once a
// withdrawal is confirmed, this contract sends an internal
// ExecuteFromExtension message to the wallet, whose sender() check is
// what actually authorizes the fund movement on the wallet side.

message ExecuteFromExtension {
    requestId: Int as uint64;
    to: Address;
    amount: Int as coins;
    body: Cell?;
    // Outbound bounce flag. False lets native TON reach an undeployed
    // (never-used) wallet, which would otherwise bounce it back.
    bounce: Bool;
}

// Expired correlation cleanup is retryable independently of request archival.
message PruneCorrelation {
    requestId: Int as uint64;
}

message WithdrawalFailed {
    requestId: Int as uint64;
}

// Guard keys (FEATURE_PLANS.md, B1) are ordinary TON wallets: they act by
// internal message and pay their own fees, so a stolen guard cannot spend
// this module's fee balance. Any value they attach tops that balance up.
// A guard can only stop things; it never moves funds or unlocks.
message(0x47554101) GuardCancelWithdrawal {
    requestId: Int as uint64;
}
message(0x47554102) GuardCancelParamChange {
    param: Int as uint8;
}
message(0x47554103) GuardCancelPendingAddress {
    destination: Address;
}
message(0x47554104) GuardDropPendingGuard {
    guard: Address;
}
message(0x47554105) GuardLock {}

struct GuardState {
    activeAt: Int as uint32;
    removableAt: Int as uint32; // 0 = no removal queued
}

struct WithdrawalRequest {
    to: Address;
    amount: Int as coins;
    // null = native TON. Otherwise the address of THIS wallet's own
    // jetton-wallet contract for the token being withdrawn (the standard
    // TEP-74 pattern: every jetton holder, including AvelockWallet, has
    // its own per-jetton wallet contract; you transfer BY messaging that
    // contract, not the jetton master).
    jettonWallet: Address?;
    // null unless this request withdraws an NFT (TEP-62). Unlike jettons,
    // an NFT has no separate per-holder wallet contract — the item
    // contract itself tracks `owner_address`, so this is the NFT item's
    // OWN address, the thing we message directly to transfer it.
    // `amount`/`jettonWallet` are unused for an NFT withdrawal.
    nftItemAddress: Address?;
    availableAt: Int as uint32;
    expiresAt: Int as uint32;
    // Submitted is not proof of settlement on an asynchronous chain.
    submitted: Bool;
    failed: Bool;
    cancelled: Bool;
    // Optional TEP-standard text comment (op 0 + UTF-8), e.g. an exchange
    // deposit memo. Native TON: the transfer body. Jetton/NFT: forward_payload.
    comment: Cell?;
    // Native TON only: send bounceable (safe default) or not. Asset hops
    // always go to a deployed jetton-wallet/NFT item and stay bounceable.
    bounceable: Bool;
}

// Owner-approved transfer targets, separate from payment destinations.
// rootAddress identifies the expected master/collection for client verification;
// it is not an on-chain attestation of arbitrary third-party code.
struct AssetRegistration {
    kind: Int as uint8;
    rootAddress: Address;
    activeAt: Int as uint32;
}

struct PendingParamChange {
    newValue: Int as uint32;
    effectiveAt: Int as uint32;
    exists: Bool;
}

const OP_ADD_ALLOWED_ADDRESS: Int = 1;
const OP_REMOVE_ALLOWED_ADDRESS: Int = 2;
const OP_REQUEST_WITHDRAWAL: Int = 3;
const OP_CANCEL_WITHDRAWAL: Int = 4;
const OP_CONFIRM_WITHDRAWAL: Int = 5;
const OP_SET_WITHDRAWAL_DELAY: Int = 6;
const OP_SET_ADDRESS_DELAY: Int = 7;
const OP_SET_POLICY_DELAY: Int = 8;
const OP_APPLY_PARAM_CHANGE: Int = 9;
const OP_CANCEL_PARAM_CHANGE: Int = 10;
const OP_SET_CONFIRMATION_WINDOW: Int = 11;
const OP_PRUNE_REQUEST: Int = 12;
const OP_PROPOSE_OWNER_ROTATION: Int = 13;
const OP_APPLY_OWNER_ROTATION: Int = 14;
const OP_CANCEL_OWNER_ROTATION: Int = 15;
const OP_REGISTER_ASSET: Int = 16;
const OP_REVOKE_ASSET: Int = 17;
const OP_ADD_GUARD: Int = 18;
const OP_REMOVE_GUARD: Int = 19;
const OP_CANCEL_GUARD_REMOVAL: Int = 20;
const OP_FINALIZE_GUARD_REMOVAL: Int = 21;
const OP_LOCK: Int = 22;
const OP_UNLOCK: Int = 23;
const OP_SET_LOCK_DELAY: Int = 24;

const PARAM_WITHDRAWAL_DELAY: Int = 0;
const PARAM_ADDRESS_DELAY: Int = 1;
const PARAM_POLICY_DELAY: Int = 2;
const PARAM_CONFIRMATION_WINDOW: Int = 3;
const PARAM_LOCK_DELAY: Int = 4;

const MAX_GUARDS: Int = 2;
const DEFAULT_LOCK_DELAY: Int = 604800; // 7 days
// features() bit 0: guard keys and Panic Lock.
const FEATURE_GUARDS_AND_LOCK: Int = 1;

// Standard TEP-74 jetton transfer opcode.
const JETTON_TRANSFER_OP: Int = 0x0f8a7ea5;
// Standard TEP-62 NFT item transfer opcode.
const NFT_TRANSFER_OP: Int = 0x5fcc3d14;

// What kind of asset a withdrawal request moves — carried as a 2-bit
// discriminant in the external message rather than a single hasJetton
// bit, now that there are two non-native asset kinds to distinguish.
const ASSET_NATIVE: Int = 0;
const ASSET_JETTON: Int = 1;
const ASSET_NFT: Int = 2;

const MAX_DELAY: Int = 7776000; // 90 days
const MAX_CONFIRMATION_WINDOW: Int = 2592000; // 30 days
// How long submitted or expired-unconfirmed records are retained.
// Archival does not certify settlement. Records can be pruned — bounds unbounded
// storage growth from years of use without erasing recent history.
const REQUEST_RETENTION: Int = 15724800; // 182 days

contract AvelockSecurityExtension {
    seqno: Int as uint32;
    lastOperationHash: Int as uint256 = 0;
    // Signed operations that were accepted (nonce consumed) but failed.
    lastFailedOperationHash: Int as uint256 = 0;
    lastFailureCode: Int as int32 = 0;
    ownerPublicKey: Int as uint256;
    networkGlobalId: Int as int32;
    requestOperation: map<Int as uint64, Int as uint32>;
    walletAddress: Address;

    withdrawalDelay: Int as uint32;
    addressDelay: Int as uint32;
    confirmationWindow: Int as uint32;
    policyDelay: Int as uint32;

    // Permanent floors fixed at deployment — see threat-model section 14.
    // No op code exists to change these, ever.
    minWithdrawalDelay: Int as uint32;
    minAddressDelay: Int as uint32;

    allowlistActiveAt: map<Address, Int as uint32>;
    allowlistEpoch: map<Address, Int as uint64>;
    requestEpoch: map<Int as uint64, Int as uint64>;
    requestAssetEpoch: map<Int as uint64, Int as uint64>;
    registeredAssets: map<Address, AssetRegistration>;
    assetEpochs: map<Address, Int as uint64>;
    nextRequestId: Int as uint64;
    requests: map<Int as uint64, WithdrawalRequest>;
    requestIdByOperation: map<Int as uint32, Int as uint64>;
    pendingParamChanges: map<Int as uint8, PendingParamChange>;

    // Guard keys and Panic Lock (FEATURE_PLANS.md, B1/B2).
    guards: map<Address, GuardState>;
    lockDelay: Int as uint32;
    locked: Bool = false;
    unlockAfter: Int as uint32 = 0;
    // Bumped by every lock: requests, pending destinations and pending
    // asset registrations from before a lock can no longer be used.
    lockEpoch: Int as uint32 = 0;
    lockTimes: map<Int as uint32, Int as uint32>;
    requestLockEpoch: map<Int as uint64, Int as uint32>;
    allowlistLockEpoch: map<Address, Int as uint32>;
    assetLockEpoch: map<Address, Int as uint32>;

    init(
        ownerPublicKey: Int,
        networkGlobalId: Int,
        walletAddress: Address,
        withdrawalDelay: Int,
        addressDelay: Int,
        confirmationWindow: Int,
        policyDelay: Int,
        minWithdrawalDelay: Int,
        minAddressDelay: Int,
    ) {
        throwUnless(50, withdrawalDelay >= minWithdrawalDelay);
        throwUnless(51, addressDelay >= minAddressDelay);

        throwUnless(61, minWithdrawalDelay > 0 && minAddressDelay > 0 && ownerPublicKey != 0);
        self.seqno = 0;
        self.ownerPublicKey = ownerPublicKey;
        throwUnless(65, networkGlobalId == chainGlobalId());
        self.networkGlobalId = networkGlobalId;
        self.walletAddress = walletAddress;
        self.withdrawalDelay = withdrawalDelay;
        self.addressDelay = addressDelay;
        self.confirmationWindow = confirmationWindow;
        self.policyDelay = policyDelay;
        self.minWithdrawalDelay = minWithdrawalDelay;
        self.minAddressDelay = minAddressDelay;
        // Lifting a lock waits at least as long as a withdrawal would.
        self.lockDelay = DEFAULT_LOCK_DELAY;
        if (withdrawalDelay > DEFAULT_LOCK_DELAY) { self.lockDelay = withdrawalDelay; }
        self.nextRequestId = 0;
        self._validate(PARAM_WITHDRAWAL_DELAY, withdrawalDelay);
        self._validate(PARAM_ADDRESS_DELAY, addressDelay);
        self._validate(PARAM_POLICY_DELAY, policyDelay);
        self._validate(PARAM_CONFIRMATION_WINDOW, confirmationWindow);

    }

    receive() {}

    // Operational-balance top-ups may carry a text comment; accept them
    // instead of bouncing (exit 130). No state change.
    receive(msg: Slice) {}

    external(msg: Slice) {
        let signature: Slice = msg.loadBits(512);
        msg = msg.loadRef().beginParse();
        let operationHash: Int = msg.hash();
        throwUnless(35, checkSignature(operationHash, signature, self.ownerPublicKey));
        throwUnless(39, msg.loadAddress() == myAddress());
        throwUnless(65, msg.loadInt(32) == self.networkGlobalId && self.networkGlobalId == chainGlobalId());
        throwUnless(36, msg.loadUint(32) == self.seqno);
        let validUntil: Int = msg.loadUint(32);
        throwUnless(37, validUntil > 0 && now() <= validUntil && validUntil <= now() + 3600);
        let op: Int = msg.loadUint(8);
        // Reserved rotation operations never accept gas or consume a nonce.
        throwUnless(68, op < OP_PROPOSE_OWNER_ROTATION || op > OP_CANCEL_OWNER_ROTATION);
        acceptMessage();
        // Consume the nonce before running the operation. If the operation
        // throws, try/catch discards its partial changes but keeps this
        // increment, so the same signed message can't be replayed to burn
        // the module's gas balance (it fails the seqno check pre-accept).
        self.seqno += 1;
        try {
        if (op == OP_REGISTER_ASSET) {
            throwUnless(71, !self.locked);
            let asset: Address = msg.loadAddress();
            let kind: Int = msg.loadUint(2);
            let rootAddress: Address = msg.loadRef().beginParse().loadAddress();
            throwUnless(61, kind == ASSET_JETTON || kind == ASSET_NFT);
            let existing: AssetRegistration? = self.registeredAssets.get(asset);
            if (existing != null && self._voidedByLock(self.assetLockEpoch.get(asset), existing!!.activeAt)) {
                // Voided by a lock while still waiting: register again, wait again.
                self.assetEpochs.set(asset, self.assetEpoch(asset) + 1);
                existing = null;
            }
            if (existing == null) {
                self.assetLockEpoch.set(asset, self.lockEpoch);
                // This target receives real TON fees. Client getter checks are
                // not proofs, so never shorten the old destination protection.
                let delay: Int = self.policyDelay;
                if (self.addressDelay > delay) { delay = self.addressDelay; }
                self.registeredAssets.set(asset, AssetRegistration{
                    kind: kind, rootAddress: rootAddress, activeAt: now() + delay,
                });
            } else {
                // Editing requires explicit revocation, invalidating old requests.
                throwUnless(67, existing!!.kind == kind && existing!!.rootAddress == rootAddress);
            }
        } else if (op == OP_REVOKE_ASSET) {
            let asset: Address = msg.loadAddress();
            self.assetEpochs.set(asset, self.assetEpoch(asset) + 1);
            self.registeredAssets.set(asset, null);
        } else if (op == OP_ADD_ALLOWED_ADDRESS) {
            throwUnless(71, !self.locked);
            let destination: Address = msg.loadAddress();
            let current: Int? = self.allowlistActiveAt.get(destination);
            if (current != null && self._voidedByLock(self.allowlistLockEpoch.get(destination), current!!)) {
                self.allowlistEpoch.set(destination, self.epoch(destination) + 1);
                current = null;
            }
            if (current == null) {
                self.allowlistActiveAt.set(destination, now() + self.addressDelay);
                self.allowlistLockEpoch.set(destination, self.lockEpoch);
            }
        } else if (op == OP_REMOVE_ALLOWED_ADDRESS) {
            let destination: Address = msg.loadAddress();
            self.allowlistEpoch.set(destination, self.epoch(destination) + 1);
            self.allowlistActiveAt.set(destination, null);
        } else if (op == OP_REQUEST_WITHDRAWAL) {
            throwUnless(71, !self.locked);
            let to: Address = msg.loadAddress();
            let amount: Int = msg.loadCoins();
            // Keep the optional asset address in a reference so the signed
            // domain/header/destination payload remains within the cell bit limit.
            let assetKind: Int = msg.loadUint(2);
            let jettonWallet: Address? = null;
            let nftItemAddress: Address? = null;
            if (assetKind == ASSET_JETTON) {
                let assetRef: Slice = msg.loadRef().beginParse();
                jettonWallet = assetRef.loadAddress();
            } else if (assetKind == ASSET_NFT) {
                let assetRef: Slice = msg.loadRef().beginParse();
                nftItemAddress = assetRef.loadAddress();
            }
            // Optional text comment, carried in its own reference.
            let comment: Cell? = msg.loadMaybeRef();
            if (comment != null) {
                let c: Slice = comment!!.beginParse();
                // Text comments only (op 0), single cell (≤123 bytes) — no
                // arbitrary message bodies to allowlisted contracts, and no
                // unbounded storage in request records.
                throwUnless(69, c.bits() >= 32 && c.loadUint(32) == 0 && c.refs() == 0);
                // A bounce is matched to its request by the 64 bits after the
                // op (audit M-2). Request ids never reach 2^56, so text that
                // starts with a non-zero byte can never be read as one — and a
                // text comment has no reason to start with a NUL.
                throwUnless(69, c.bits() == 0 || c.preloadUint(8) != 0);
            }
            let bounceable: Bool = msg.loadBool();
            // Non-bounceable delivery is only meaningful for native TON.
            throwUnless(70, bounceable || assetKind == ASSET_NATIVE);
            throwUnless(61, assetKind <= ASSET_NFT && (assetKind == ASSET_NFT || amount > 0));
            throwUnless(52, self.isAddressActive(to));
            self.requestEpoch.set(self.nextRequestId, self.epoch(to));
            self.requestLockEpoch.set(self.nextRequestId, self.lockEpoch);
            let asset: Address? = jettonWallet;
            if (nftItemAddress != null) { asset = nftItemAddress; }
            if (asset != null) {
                throwUnless(67, self.isAssetActive(asset!!, assetKind));
                self.requestAssetEpoch.set(self.nextRequestId, self.assetEpoch(asset!!));
            }

            let availableAt: Int = now() + self.withdrawalDelay;
            let expiresAt: Int = availableAt + self.confirmationWindow;
            self.requests.set(self.nextRequestId, WithdrawalRequest{
                to: to,
                amount: amount,
                jettonWallet: jettonWallet,
                nftItemAddress: nftItemAddress,
                availableAt: availableAt,
                expiresAt: expiresAt,
                submitted: false,
                failed: false,
                cancelled: false,
                comment: comment,
                bounceable: bounceable,
            });
            self.requestIdByOperation.set(self.seqno - 1, self.nextRequestId);
            self.requestOperation.set(self.nextRequestId, self.seqno - 1);
            self.nextRequestId += 1;
        } else if (op == OP_CANCEL_WITHDRAWAL) {
            let requestId: Int = msg.loadUint(64);
            let req: WithdrawalRequest = self.requests.get(requestId)!!;
            throwUnless(53, !req.submitted && !req.cancelled);
            req.cancelled = true;
            self.requests.set(requestId, req);
        } else if (op == OP_PRUNE_REQUEST) {
            // Archival is not settlement. After retention, late failure
            // reporting ends; archived IDs can never be submitted again.
            let requestId: Int = msg.loadUint(64);
            let req: WithdrawalRequest = self.requests.get(requestId)!!;
            let annulled: Bool = self.isRequestAnnulled(requestId);
            let terminal: Bool = req.cancelled || req.submitted || annulled || now() > req.expiresAt;
            let retentionOk: Bool = req.cancelled || annulled || now() > req.expiresAt + REQUEST_RETENTION;
            throwUnless(66, terminal && retentionOk);
            if (req.submitted) {
                send(SendParameters{
                    to: self.walletAddress, value: ton("0.01"), mode: SendPayGasSeparately,
                    body: PruneCorrelation{ requestId: requestId }.toCell(),
                });
            }
            let operation: Int? = self.requestOperation.get(requestId);
            if (operation != null) { self.requestIdByOperation.set(operation!!, null); }
            self.requestOperation.set(requestId, null);
            self.requests.set(requestId, null);
            self.requestEpoch.set(requestId, null);
            self.requestAssetEpoch.set(requestId, null);
            self.requestLockEpoch.set(requestId, null);
        } else if (op == OP_CONFIRM_WITHDRAWAL) {
            throwUnless(71, !self.locked);
            throwUnless(64, myBalance() >= ton("0.07"));
            let requestId: Int = msg.loadUint(64);
            let req: WithdrawalRequest = self.requests.get(requestId)!!;
            throwUnless(53, !req.submitted && !req.cancelled);
            throwUnless(72, !self.isRequestAnnulled(requestId));
            throwUnless(54, now() >= req.availableAt);
            throwUnless(55, now() <= req.expiresAt);

            throwUnless(52, self.isAddressActive(req.to) && self.requestEpoch.get(requestId) == self.epoch(req.to));
            let asset: Address? = req.jettonWallet;
            if (req.nftItemAddress != null) { asset = req.nftItemAddress; }
            if (asset != null) {
                let kind: Int = ASSET_JETTON;
                if (req.nftItemAddress != null) { kind = ASSET_NFT; }
                throwUnless(67, self.isAssetActive(asset!!, kind) && self.requestAssetEpoch.get(requestId) == self.assetEpoch(asset!!));
            }
            req.submitted = true;
            req.failed = false;
            self.requests.set(requestId, req);

            // The withdrawn amount already lives in the wallet's own
            // balance (that's where user funds sit) — this message only
            // needs enough value to cover its own forwarding/processing
            // gas, paid out of the extension's balance, separately from
            // the wallet's subsequent send of `req.amount` (or jettons)
            // to `req.to`.
            if (req.jettonWallet == null && req.nftItemAddress == null) {
                send(SendParameters{
                    to: self.walletAddress,
                    // The wallet's processing costs ~0.001 TON; the rest stays in the Vault.
                    value: ton("0.01"),
                    mode: SendPayGasSeparately,
                    // With a comment the body is a plain text comment, so the
                    // wallet can't correlate a destination-side bounce to this
                    // request; the TON still returns to the Vault. See SECURITY.md.
                    body: ExecuteFromExtension{ requestId: requestId, to: req.to, amount: req.amount, body: req.comment, bounce: req.bounceable }.toCell(),
                });
            } else if (req.jettonWallet != null) {
                // Jettons: the wallet holds them via its OWN per-jetton
                // wallet contract (req.jettonWallet). We can't transfer
                // "value" of a jetton directly — we instruct the wallet
                // to message its jetton-wallet contract with a standard
                // TEP-74 transfer body. Failure modes are handled by the
                // jetton-wallet standard itself (insufficient balance
                // bounces the message back), unlike EVM's silent
                // false-return risk.
                let jettonBody: Cell = beginCell()
                    .storeUint(JETTON_TRANSFER_OP, 32)
                    .storeUint(requestId, 64)
                    .storeCoins(req.amount)
                    .storeAddress(req.to)
                    .storeAddress(self.walletAddress)
                    .storeUint(0, 1)
                    // forward_ton_amount > 0 so the recipient receives a
                    // transfer_notification carrying the comment (exchanges
                    // read the memo from it).
                    .storeCoins(req.comment == null ? 0 : 1)
                    .storeSlice(self._forwardPayload(req.comment))
                    .endCell();

                send(SendParameters{
                    to: self.walletAddress,
                    // 0.05 is forwarded to the jetton wallet / NFT item (the
                    // standard transfer budget), ~0.001 is the wallet's own gas.
                    value: ton("0.06"),
                    mode: SendPayGasSeparately,
                    body: ExecuteFromExtension{ requestId: requestId, to: req.jettonWallet!!, amount: ton("0.05"), body: jettonBody, bounce: true }.toCell(),
                });
            } else {
                // NFTs (TEP-62): unlike jettons, the wallet holds the item
                // directly — req.nftItemAddress IS the item's own contract
                // (there's no separate per-holder wallet the way jettons
                // have one). A standard `transfer` message reassigns
                // owner_address to req.to; a small forward_amount notifies
                // the new owner's wallet so the transfer shows up the same
                // way any other NFT transfer would in their client.
                let nftBody: Cell = beginCell()
                    .storeUint(NFT_TRANSFER_OP, 32)
                    .storeUint(requestId, 64)
                    .storeAddress(req.to)
                    .storeAddress(self.walletAddress)
                    .storeUint(0, 1)
                    .storeCoins(1)
                    .storeSlice(self._forwardPayload(req.comment))
                    .endCell();

                send(SendParameters{
                    to: self.walletAddress,
                    // 0.05 is forwarded to the jetton wallet / NFT item (the
                    // standard transfer budget), ~0.001 is the wallet's own gas.
                    value: ton("0.06"),
                    mode: SendPayGasSeparately,
                    body: ExecuteFromExtension{ requestId: requestId, to: req.nftItemAddress!!, amount: ton("0.05"), body: nftBody, bounce: true }.toCell(),
                });
            }
        } else if (op == OP_SET_WITHDRAWAL_DELAY) {
            throwUnless(71, !self.locked);
            let newValue: Int = msg.loadUint(32);
            throwUnless(56, newValue >= self.minWithdrawalDelay);
            self._proposeChange(PARAM_WITHDRAWAL_DELAY, newValue, self.withdrawalDelay);
        } else if (op == OP_SET_ADDRESS_DELAY) {
            throwUnless(71, !self.locked);
            let newValue: Int = msg.loadUint(32);
            throwUnless(57, newValue >= self.minAddressDelay);
            self._proposeChange(PARAM_ADDRESS_DELAY, newValue, self.addressDelay);
        } else if (op == OP_SET_POLICY_DELAY) {
            throwUnless(71, !self.locked);
            let newValue: Int = msg.loadUint(32);
            self._proposeChange(PARAM_POLICY_DELAY, newValue, self.policyDelay);
        } else if (op == OP_SET_CONFIRMATION_WINDOW) {
            throwUnless(71, !self.locked);
            let newValue: Int = msg.loadUint(32);
            self._proposeChange(PARAM_CONFIRMATION_WINDOW, newValue, self.confirmationWindow);
        } else if (op == OP_APPLY_PARAM_CHANGE) {
            throwUnless(71, !self.locked);
            let param: Int = msg.loadUint(8);
            let pending: PendingParamChange = self.pendingParamChanges.get(param)!!;
            throwUnless(58, pending.exists);
            throwUnless(59, now() >= pending.effectiveAt);
            self._writeParam(param, pending.newValue);
            self.pendingParamChanges.set(param, null);
        } else if (op == OP_CANCEL_PARAM_CHANGE) {
            let param: Int = msg.loadUint(8);
            let pending: PendingParamChange = self.pendingParamChanges.get(param)!!;
            throwUnless(58, pending.exists);
            self.pendingParamChanges.set(param, null);
        } else if (op == OP_SET_LOCK_DELAY) {
            throwUnless(71, !self.locked);
            let newValue: Int = msg.loadUint(32);
            throwUnless(56, newValue >= self.minWithdrawalDelay);
            self._proposeChange(PARAM_LOCK_DELAY, newValue, self.lockDelay);
        } else if (op == OP_ADD_GUARD) {
            throwUnless(71, !self.locked);
            let key: Address = msg.loadAddress();
            throwUnless(74, self.guards.get(key) == null && self._guardCount() < MAX_GUARDS);
            self.guards.set(key, GuardState{ activeAt: now() + self.addressDelay, removableAt: 0 });
        } else if (op == OP_REMOVE_GUARD) {
            // A guard still waiting goes at once; an active one waits the
            // address delay, so a stolen owner key can't quietly drop it.
            let key: Address = msg.loadAddress();
            let g: GuardState = self.guards.get(key)!!;
            if (now() < g.activeAt) {
                self.guards.set(key, null);
            } else if (g.removableAt == 0) {
                // Queued only while unlocked; a lock drops it (audit A15-1).
                throwUnless(71, !self.locked);
                self.guards.set(key, GuardState{ activeAt: g.activeAt, removableAt: now() + self.addressDelay });
            }
        } else if (op == OP_CANCEL_GUARD_REMOVAL) {
            let key: Address = msg.loadAddress();
            let g: GuardState = self.guards.get(key)!!;
            throwUnless(75, g.removableAt != 0);
            self.guards.set(key, GuardState{ activeAt: g.activeAt, removableAt: 0 });
        } else if (op == OP_FINALIZE_GUARD_REMOVAL) {
            let key: Address = msg.loadAddress();
            let g: GuardState = self.guards.get(key)!!;
            throwUnless(75, g.removableAt != 0);
            throwUnless(59, now() >= g.removableAt);
            // Never during a lock (audit A15-1): else a phrase thief waits out
            // the guard's lock and no one is left to extend it.
            throwUnless(71, !self.locked);
            self.guards.set(key, null);
        } else if (op == OP_LOCK) {
            self._lock();
        } else if (op == OP_UNLOCK) {
            throwUnless(73, self.locked && now() >= self.unlockAfter);
            self.locked = false;
        } else {
            throw(60);
        }
            self.lastOperationHash = operationHash;
        } catch (code) {
            self.lastFailedOperationHash = operationHash;
            self.lastFailureCode = code;
        }

    }

    receive(msg: WithdrawalFailed) {
        throwUnless(38, sender() == self.walletAddress);
        let existing: WithdrawalRequest? = self.requests.get(msg.requestId);
        if (existing == null) { return; } // Archived IDs stay absent.
        let req: WithdrawalRequest = existing!!;
        req.failed = true;
        // Do not automatically retry an asynchronous asset transfer.
        self.requests.set(msg.requestId, req);
    }

    // ---- guard actions: stop-only, by internal message from a guard wallet ----

    receive(msg: GuardCancelWithdrawal) {
        throwUnless(76, self.isGuard(sender()));
        let req: WithdrawalRequest = self.requests.get(msg.requestId)!!;
        throwUnless(53, !req.submitted && !req.cancelled);
        req.cancelled = true;
        self.requests.set(msg.requestId, req);
    }

    receive(msg: GuardCancelParamChange) {
        throwUnless(76, self.isGuard(sender()));
        throwUnless(58, self.pendingParamChanges.get(msg.param) != null);
        self.pendingParamChanges.set(msg.param, null);
    }

    receive(msg: GuardCancelPendingAddress) {
        throwUnless(76, self.isGuard(sender()));
        let activeAt: Int? = self.allowlistActiveAt.get(msg.destination);
        throwUnless(75, activeAt != null && now() < activeAt!!);
        self.allowlistEpoch.set(msg.destination, self.epoch(msg.destination) + 1);
        self.allowlistActiveAt.set(msg.destination, null);
    }

    receive(msg: GuardDropPendingGuard) {
        throwUnless(76, self.isGuard(sender()));
        let g: GuardState = self.guards.get(msg.guard)!!;
        throwUnless(75, now() < g.activeAt);
        self.guards.set(msg.guard, null);
    }

    receive(msg: GuardLock) {
        throwUnless(76, self.isGuard(sender()));
        self._lock();
    }

    // Panic Lock: instant; voids pending requests, destinations and asset
    // registrations, cancels queued changes, pending guards and queued guard
    // removals. Locking
    // again extends it. Only the owner lifts it, after lockDelay.
    fun _lock() {
        let lockedUntil: Int = now() + self.lockDelay;
        if (self.locked) {
            if (lockedUntil > self.unlockAfter) { self.unlockAfter = lockedUntil; }
            return;
        }
        self.locked = true;
        self.unlockAfter = lockedUntil;
        self.lockEpoch += 1;
        self.lockTimes.set(self.lockEpoch, now());
        self.pendingParamChanges = emptyMap();
        let waiting: map<Address, Bool> = emptyMap();
        let leaving: map<Address, Int> = emptyMap();
        foreach (key, g in self.guards) {
            if (now() < g.activeAt) { waiting.set(key, true); }
            else if (g.removableAt != 0) { leaving.set(key, g.activeAt); }
        }
        foreach (key, flag in waiting) {
            self.guards.set(key, null);
        }
        // A queued removal of an active guard is void too (A15-1).
        foreach (key, activeAt in leaving) {
            self.guards.set(key, GuardState{ activeAt: activeAt, removableAt: 0 });
        }
    }

    fun _guardCount(): Int {
        let n: Int = 0;
        foreach (key, g in self.guards) { n += 1; }
        return n;
    }

    // Still waiting when the first lock after it came: void.
    fun _voidedByLock(epoch: Int?, activeAt: Int): Bool {
        let e: Int = 0;
        if (epoch != null) { e = epoch!!; }
        let lockedAt: Int? = self.lockTimes.get(e + 1);
        return lockedAt != null && lockedAt!! < activeAt;
    }

    get fun isGuard(addr: Address): Bool {
        let g: GuardState? = self.guards.get(addr);
        return g != null && now() >= g!!.activeAt;
    }

    get fun guards(): map<Address, GuardState> { return self.guards; }
    get fun locked(): Bool { return self.locked; }
    get fun unlockAfter(): Int { return self.unlockAfter; }
    get fun lockEpoch(): Int { return self.lockEpoch; }
    get fun lockDelay(): Int { return self.lockDelay; }
    get fun features(): Int { return FEATURE_GUARDS_AND_LOCK; }

    get fun isRequestAnnulled(id: Int): Bool {
        let e: Int? = self.requestLockEpoch.get(id);
        if (e == null) { return false; }
        let req: WithdrawalRequest? = self.requests.get(id);
        return e!! != self.lockEpoch && (req == null || !req!!.submitted);
    }

    get fun lastOperationHash(): Int { return self.lastOperationHash; }
    get fun lastFailedOperationHash(): Int { return self.lastFailedOperationHash; }
    get fun lastFailureCode(): Int { return self.lastFailureCode; }

    // Only a bounce from our wallet proves the first forwarding hop failed.
    bounced(msg: bounced<ExecuteFromExtension>) {
        if (sender() != self.walletAddress) { return; }
        let req: WithdrawalRequest? = self.requests.get(msg.requestId);
        if (req != null) {
            let r: WithdrawalRequest = req!!;
            r.submitted = false;
            r.failed = true;
            self.requests.set(msg.requestId, r);
        }
    }

    fun assetEpoch(addr: Address): Int {
        let value: Int? = self.assetEpochs.get(addr);
        if (value == null) { return 0; }
        return value!!;
    }

    get fun assetRegistration(addr: Address): AssetRegistration? {
        return self.registeredAssets.get(addr);
    }

    get fun isAssetActive(addr: Address, kind: Int): Bool {
        let asset: AssetRegistration? = self.registeredAssets.get(addr);
        if (asset == null) { return false; }
        return asset!!.kind == kind && now() >= asset!!.activeAt && !self._voidedByLock(self.assetLockEpoch.get(addr), asset!!.activeAt);
    }

    fun epoch(addr: Address): Int {
        let value: Int? = self.allowlistEpoch.get(addr);
        if (value == null) { return 0; }
        return value!!;
    }

    // TEP-74/TEP-62 forward_payload (Either Cell ^Cell): empty inline, or the comment by reference.
    fun _forwardPayload(comment: Cell?): Slice {
        if (comment == null) { return beginCell().storeUint(0, 1).asSlice(); }
        return beginCell().storeUint(1, 1).storeRef(comment!!).asSlice();
    }

    fun _validate(param: Int, value: Int) {
        throwUnless(61, param >= 0 && param <= PARAM_LOCK_DELAY);
        let limit: Int = MAX_DELAY;
        if (param == PARAM_CONFIRMATION_WINDOW) { limit = MAX_CONFIRMATION_WINDOW; }
        throwUnless(61, value > 0 && value <= limit);
    }

    fun _proposeChange(param: Int, newValue: Int, currentValue: Int) {
        self._validate(param, newValue);
        // Re-setting the current value withdraws a queued change of that
        // parameter (audit AVL-TON-001): any client, automation or older app
        // version that "cancels" by setting the current value really cancels.
        if (newValue == currentValue) {
            self.pendingParamChanges.set(param, null);
            return;
        }
        self.pendingParamChanges.set(param, PendingParamChange{
            newValue: newValue,
            effectiveAt: now() + self.changeWait(),
            exists: true,
        });
    }

    // A change waits the policy delay, never less than the withdrawal delay
    // (audit A14-2): else a short policy delay lowers the withdrawal delay
    // and a phrase thief withdraws sooner than the owner's delay.
    fun changeWait(): Int {
        return max(self.policyDelay, self.withdrawalDelay);
    }

    // Invariant (audit A12-3): lockDelay >= withdrawalDelay when a change
    // applies, so a lock never lifts sooner than a withdrawal could complete.
    fun _writeParam(param: Int, value: Int) {
        if (param == PARAM_WITHDRAWAL_DELAY) {
            self.withdrawalDelay = value;
            if (self.lockDelay < value) { self.lockDelay = value; }
        } else if (param == PARAM_ADDRESS_DELAY) {
            self.addressDelay = value;
        } else if (param == PARAM_CONFIRMATION_WINDOW) {
            self.confirmationWindow = value;
        } else if (param == PARAM_LOCK_DELAY) {
            self.lockDelay = value;
            if (value < self.withdrawalDelay) { self.lockDelay = self.withdrawalDelay; }
        } else {
            self.policyDelay = value;
        }
    }

    get fun addressActiveAt(addr: Address): Int {
        let activeAt: Int? = self.allowlistActiveAt.get(addr);
        if (activeAt == null) { return 0; }
        return activeAt!!;
    }

    get fun isAddressActive(addr: Address): Bool {
        let activeAt: Int? = self.allowlistActiveAt.get(addr);
        if (activeAt == null) {
            return false;
        }
        return now() >= activeAt!! && !self._voidedByLock(self.allowlistLockEpoch.get(addr), activeAt!!);
    }

    get fun walletAddress(): Address { return self.walletAddress; }

    get fun ownerPublicKey(): Int { return self.ownerPublicKey; }

    get fun protocolVersion(): Int { return 1; }
    get fun networkGlobalId(): Int { return self.networkGlobalId; }
    get fun operationalBalance(): Int { return myBalance(); }
    get fun minimumOperationalBalance(): Int { return ton("0.07"); }

    get fun seqno(): Int {
        return self.seqno;
    }

    get fun withdrawalDelay(): Int {
        return self.withdrawalDelay;
    }

    get fun addressDelay(): Int {
        return self.addressDelay;
    }

    get fun policyDelay(): Int {
        return self.policyDelay;
    }

    get fun confirmationWindow(): Int {
        return self.confirmationWindow;
    }

    get fun minWithdrawalDelay(): Int {
        return self.minWithdrawalDelay;
    }

    get fun minAddressDelay(): Int {
        return self.minAddressDelay;
    }

    get fun nextRequestId(): Int {
        return self.nextRequestId;
    }

    get fun requestIdForOperation(operationSeqno: Int): Int? {
        return self.requestIdByOperation.get(operationSeqno);
    }

    get fun request(id: Int): WithdrawalRequest? {
        return self.requests.get(id);
    }

    get fun pendingParamChange(param: Int): PendingParamChange? {
        return self.pendingParamChanges.get(param);
    }


}
