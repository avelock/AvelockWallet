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
    to: Address;
    amount: Int as coins;
    body: Cell?;
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
    availableAt: Int as uint32;
    expiresAt: Int as uint32;
    executed: Bool;
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

contract AvelockSecurityExtension {
    seqno: Int as uint32;
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
    nextRequestId: Int as uint64;
    requests: map<Int as uint64, WithdrawalRequest>;
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
    }

    receive() {}

    external(msg: Slice) {
        let signature: Slice = msg.loadBits(512);
        let signedHash: Int = msg.hash();
        throwUnless(35, checkSignature(signedHash, signature, self.ownerPublicKey));

        acceptMessage();

        let msgSeqno: Int = msg.loadUint(32);
        throwUnless(36, msgSeqno == self.seqno);
        self.seqno += 1;

        let op: Int = msg.loadUint(8);

        if (op == OP_ADD_ALLOWED_ADDRESS) {
            let destination: Address = msg.loadAddress();
            self.allowlistActiveAt.set(destination, now() + self.addressDelay);
        } else if (op == OP_REMOVE_ALLOWED_ADDRESS) {
            let destination: Address = msg.loadAddress();
            self.allowlistActiveAt.set(destination, null);
        } else if (op == OP_REQUEST_WITHDRAWAL) {
            let to: Address = msg.loadAddress();
            let amount: Int = msg.loadCoins();
            // The optional jetton-wallet address is carried in a ref cell,
            // not inline — signature(512) + seqno(32) + op(8) + two
            // addresses(267 each) would overflow a single cell's 1023-bit
            // limit otherwise.
            let hasJetton: Int = msg.loadUint(1);
            let jettonWallet: Address? = null;
            if (hasJetton == 1) {
                let jettonRef: Slice = msg.loadRef().beginParse();
                jettonWallet = jettonRef.loadAddress();
            }
            throwUnless(52, self.isAddressActive(to));

            let availableAt: Int = now() + self.withdrawalDelay;
            let expiresAt: Int = availableAt + self.confirmationWindow;
            self.requests.set(self.nextRequestId, WithdrawalRequest{
                to: to,
                amount: amount,
                jettonWallet: jettonWallet,
                availableAt: availableAt,
                expiresAt: expiresAt,
                executed: false,
                cancelled: false,
            });
            self.nextRequestId += 1;
        } else if (op == OP_CANCEL_WITHDRAWAL) {
            let requestId: Int = msg.loadUint(64);
            let req: WithdrawalRequest = self.requests.get(requestId)!!;
            throwUnless(53, !req.executed && !req.cancelled);
            req.cancelled = true;
            self.requests.set(requestId, req);
        } else if (op == OP_CONFIRM_WITHDRAWAL) {
            let requestId: Int = msg.loadUint(64);
            let req: WithdrawalRequest = self.requests.get(requestId)!!;
            throwUnless(53, !req.executed && !req.cancelled);
            throwUnless(54, now() >= req.availableAt);
            throwUnless(55, now() <= req.expiresAt);

            req.executed = true;
            self.requests.set(requestId, req);

            // The withdrawn amount already lives in the wallet's own
            // balance (that's where user funds sit) — this message only
            // needs enough value to cover its own forwarding/processing
            // gas, paid out of the extension's balance, separately from
            // the wallet's subsequent send of `req.amount` (or jettons)
            // to `req.to`.
            if (req.jettonWallet == null) {
                send(SendParameters{
                    to: self.walletAddress,
                    value: ton("0.05"),
                    mode: SendPayGasSeparately,
                    body: ExecuteFromExtension{ to: req.to, amount: req.amount, body: null }.toCell(),
                });
            } else {
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
                    .storeUint(0, 64)
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
                    body: ExecuteFromExtension{ to: req.jettonWallet!!, amount: ton("0.05"), body: jettonBody }.toCell(),
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

        commit();
    }

    fun _proposeChange(param: Int, newValue: Int, currentValue: Int) {
        if (newValue >= currentValue) {
            self.pendingParamChanges.set(param, null);
            self._writeParam(param, newValue);
        } else {
            self.pendingParamChanges.set(param, PendingParamChange{
                newValue: newValue,
                effectiveAt: now() + self.policyDelay,
                exists: true,
            });
        }
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

    get fun isAddressActive(addr: Address): Bool {
        let activeAt: Int? = self.allowlistActiveAt.get(addr);
        if (activeAt == null) {
            return false;
        }
        return now() >= activeAt!!;
    }

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

    get fun request(id: Int): WithdrawalRequest? {
        return self.requests.get(id);
    }

    get fun pendingParamChange(param: Int): PendingParamChange? {
        return self.pendingParamChanges.get(param);
    }
}
