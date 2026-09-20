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
}

message WithdrawalFailed {
    requestId: Int as uint64;
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

const PARAM_WITHDRAWAL_DELAY: Int = 0;
const PARAM_ADDRESS_DELAY: Int = 1;
const PARAM_POLICY_DELAY: Int = 2;
const PARAM_CONFIRMATION_WINDOW: Int = 3;

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

contract AvelockSecurityExtension {
    seqno: Int as uint32;
    lastOperationHash: Int as uint256 = 0;
    ownerPublicKey: Int as uint256;
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
    nextRequestId: Int as uint64;
    requests: map<Int as uint64, WithdrawalRequest>;
    requestIdByOperation: map<Int as uint32, Int as uint64>;
    pendingParamChanges: map<Int as uint8, PendingParamChange>;

    init(
        ownerPublicKey: Int,
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

        throwUnless(61, minWithdrawalDelay > 0 && minAddressDelay > 0);
        self.seqno = 0;
        self.ownerPublicKey = ownerPublicKey;
        self.walletAddress = walletAddress;
        self.withdrawalDelay = withdrawalDelay;
        self.addressDelay = addressDelay;
        self.confirmationWindow = confirmationWindow;
        self.policyDelay = policyDelay;
        self.minWithdrawalDelay = minWithdrawalDelay;
        self.minAddressDelay = minAddressDelay;
        self.nextRequestId = 0;
        self._validate(PARAM_WITHDRAWAL_DELAY, withdrawalDelay);
        self._validate(PARAM_ADDRESS_DELAY, addressDelay);
        self._validate(PARAM_POLICY_DELAY, policyDelay);
        self._validate(PARAM_CONFIRMATION_WINDOW, confirmationWindow);

    }

    receive() {}

    external(msg: Slice) {
        let signature: Slice = msg.loadBits(512);
        msg = msg.loadRef().beginParse();
        let operationHash: Int = msg.hash();
        throwUnless(35, checkSignature(operationHash, signature, self.ownerPublicKey));
        throwUnless(39, msg.loadAddress() == myAddress());
        throwUnless(36, msg.loadUint(32) == self.seqno);
        let validUntil: Int = msg.loadUint(32);
        throwUnless(37, validUntil > 0 && now() <= validUntil && validUntil <= now() + 3600);
        acceptMessage();
        self.lastOperationHash = operationHash;
        self.seqno += 1;

        let op: Int = msg.loadUint(8);

        if (op == OP_ADD_ALLOWED_ADDRESS) {
            let destination: Address = msg.loadAddress();
            if (self.allowlistActiveAt.get(destination) == null) {
                self.allowlistActiveAt.set(destination, now() + self.addressDelay);
            }
        } else if (op == OP_REMOVE_ALLOWED_ADDRESS) {
            let destination: Address = msg.loadAddress();
            self.allowlistEpoch.set(destination, self.epoch(destination) + 1);
            self.allowlistActiveAt.set(destination, null);
        } else if (op == OP_REQUEST_WITHDRAWAL) {
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
            throwUnless(61, assetKind <= ASSET_NFT && (assetKind == ASSET_NFT || amount > 0));
            throwUnless(52, self.isAddressActive(to));
            self.requestEpoch.set(self.nextRequestId, self.epoch(to));
            let asset: Address? = jettonWallet;
            if (nftItemAddress != null) { asset = nftItemAddress; }
            if (asset != null) {
                // Every TON recipient, including an asset contract receiving gas, is delayed/allowlisted.
                throwUnless(52, self.isAddressActive(asset!!));
                self.requestAssetEpoch.set(self.nextRequestId, self.epoch(asset!!));
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
            });
            self.requestIdByOperation.set(self.seqno - 1, self.nextRequestId);
            self.nextRequestId += 1;
        } else if (op == OP_CANCEL_WITHDRAWAL) {
            let requestId: Int = msg.loadUint(64);
            let req: WithdrawalRequest = self.requests.get(requestId)!!;
            throwUnless(53, !req.submitted && !req.cancelled);
            req.cancelled = true;
            self.requests.set(requestId, req);
        } else if (op == OP_CONFIRM_WITHDRAWAL) {
            let requestId: Int = msg.loadUint(64);
            let req: WithdrawalRequest = self.requests.get(requestId)!!;
            throwUnless(53, !req.submitted && !req.cancelled);
            throwUnless(54, now() >= req.availableAt);
            throwUnless(55, now() <= req.expiresAt);

            throwUnless(52, self.isAddressActive(req.to) && self.requestEpoch.get(requestId) == self.epoch(req.to));
            let asset: Address? = req.jettonWallet;
            if (req.nftItemAddress != null) { asset = req.nftItemAddress; }
            if (asset != null) {
                throwUnless(52, self.isAddressActive(asset!!) && self.requestAssetEpoch.get(requestId) == self.epoch(asset!!));
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
                    value: ton("0.05"),
                    mode: SendPayGasSeparately,
                    body: ExecuteFromExtension{ requestId: requestId, to: req.to, amount: req.amount, body: null }.toCell(),
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
                    .storeCoins(0)
                    .storeUint(0, 1)
                    .endCell();

                send(SendParameters{
                    to: self.walletAddress,
                    value: ton("0.08"),
                    mode: SendPayGasSeparately,
                    body: ExecuteFromExtension{ requestId: requestId, to: req.jettonWallet!!, amount: ton("0.05"), body: jettonBody }.toCell(),
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
                    .storeUint(0, 1)
                    .endCell();

                send(SendParameters{
                    to: self.walletAddress,
                    value: ton("0.08"),
                    mode: SendPayGasSeparately,
                    body: ExecuteFromExtension{ requestId: requestId, to: req.nftItemAddress!!, amount: ton("0.05"), body: nftBody }.toCell(),
                });
            }
        } else if (op == OP_SET_WITHDRAWAL_DELAY) {
            let newValue: Int = msg.loadUint(32);
            throwUnless(56, newValue >= self.minWithdrawalDelay);
            self._proposeChange(PARAM_WITHDRAWAL_DELAY, newValue, self.withdrawalDelay);
        } else if (op == OP_SET_ADDRESS_DELAY) {
            let newValue: Int = msg.loadUint(32);
            throwUnless(57, newValue >= self.minAddressDelay);
            self._proposeChange(PARAM_ADDRESS_DELAY, newValue, self.addressDelay);
        } else if (op == OP_SET_POLICY_DELAY) {
            let newValue: Int = msg.loadUint(32);
            self._proposeChange(PARAM_POLICY_DELAY, newValue, self.policyDelay);
        } else if (op == OP_SET_CONFIRMATION_WINDOW) {
            let newValue: Int = msg.loadUint(32);
            self._proposeChange(PARAM_CONFIRMATION_WINDOW, newValue, self.confirmationWindow);
        } else if (op == OP_APPLY_PARAM_CHANGE) {
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
        } else {
            throw(60);
        }

    }

    receive(msg: WithdrawalFailed) {
        throwUnless(38, sender() == self.walletAddress);
        let req: WithdrawalRequest = self.requests.get(msg.requestId)!!;
        req.failed = true;
        // Do not automatically retry an asynchronous asset transfer.
        self.requests.set(msg.requestId, req);
    }

    get fun lastOperationHash(): Int { return self.lastOperationHash; }

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

    fun epoch(addr: Address): Int {
        let value: Int? = self.allowlistEpoch.get(addr);
        if (value == null) { return 0; }
        return value!!;
    }

    fun _validate(param: Int, value: Int) {
        throwUnless(61, param >= 0 && param <= PARAM_CONFIRMATION_WINDOW);
        let limit: Int = MAX_DELAY;
        if (param == PARAM_CONFIRMATION_WINDOW) { limit = MAX_CONFIRMATION_WINDOW; }
        throwUnless(61, value > 0 && value <= limit);
    }

    fun _proposeChange(param: Int, newValue: Int, currentValue: Int) {
        self._validate(param, newValue);
        if (newValue == currentValue) { return; }
        self.pendingParamChanges.set(param, PendingParamChange{
            newValue: newValue,
            effectiveAt: now() + self.policyDelay,
            exists: true,
        });
    }

    fun _writeParam(param: Int, value: Int) {
        if (param == PARAM_WITHDRAWAL_DELAY) {
            self.withdrawalDelay = value;
        } else if (param == PARAM_ADDRESS_DELAY) {
            self.addressDelay = value;
        } else if (param == PARAM_CONFIRMATION_WINDOW) {
            self.confirmationWindow = value;
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
        return now() >= activeAt!!;
    }

    get fun walletAddress(): Address { return self.walletAddress; }

    get fun ownerPublicKey(): Int { return self.ownerPublicKey; }

    get fun protocolVersion(): Int { return 2; }

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
