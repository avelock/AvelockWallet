// ============================================================
// Avelock Wallet
// Self-custody vault with on-chain withdrawal delays.
// https://github.com/avelock/AvelockWallet
// ============================================================

import "./avelock_security_extension.tact";

contract AvelockWallet {
    seqno: Int as uint32;
    ownerPublicKey: Int as uint256;
    networkGlobalId: Int as int32;
    extensions: map<Address, Bool>;
    initialized: Bool = false;
    destinations: map<Int as uint64, Address>;
    correlationCreatedAt: map<Int as uint64, Int as uint32>;
    module: Address?;

    init(
        ownerPublicKey: Int,
        networkGlobalId: Int,
        withdrawalDelay: Int,
        addressDelay: Int,
        confirmationWindow: Int,
        policyDelay: Int,
        minWithdrawalDelay: Int,
        minAddressDelay: Int,
    ) {
        self.seqno = 0;
        self.ownerPublicKey = ownerPublicKey;
        throwUnless(65, networkGlobalId == chainGlobalId());
        self.networkGlobalId = networkGlobalId;
        let trusted: Address = contractAddress(initOf AvelockSecurityExtension(
            ownerPublicKey, networkGlobalId, myAddress(),
            withdrawalDelay, addressDelay, confirmationWindow, policyDelay,
            minWithdrawalDelay, minAddressDelay
        ));
        self.module = trusted;
        self.extensions.set(trusted, true);
        self.initialized = true;
    }

    // Accept plain TON transfers with no restriction — incoming funds are
    // never subject to a delay (mirrors receive() on the EVM side). TON
    // credits the contract's balance automatically; this handler simply
    // needs to exist and do nothing, since cashback()/reject would send
    // the deposit straight back to the sender instead of keeping it.
    receive() {}

    // Only the installed security module may request a transfer.
    receive(msg: ExecuteFromExtension) {
        throwUnless(38, self.extensions.get(sender()) == true);
        self.destinations.set(msg.requestId, msg.to);
        self.correlationCreatedAt.set(msg.requestId, now());
        let body: Cell? = msg.body;
        if (body == null) {
            body = beginCell().storeUint(0, 32).storeUint(msg.requestId, 64).endCell();
        }
        send(SendParameters{ to: msg.to, value: msg.amount, mode: SendPayGasSeparately | SendBounceIfActionFail, body: body });
    }

    // Anyone may pay to clear expired diagnostics. This grants no spending
    // authority and cannot remove correlation during the retention period.
    receive(msg: PruneCorrelation) {
        let createdAt: Int? = self.correlationCreatedAt.get(msg.requestId);
        if (createdAt == null) { return; }
        throwUnless(66, now() > createdAt!! + REQUEST_RETENTION);
        self.destinations.set(msg.requestId, null);
        self.correlationCreatedAt.set(msg.requestId, null);
    }

    get fun correlationDestination(requestId: Int): Address? {
        return self.destinations.get(requestId);
    }

    // Only the installed security module may rotate the display copy of
    // the owner key — see RotateOwner in avelock_security_extension.tact.
    // The module's OWN key is the real signing authority; this keeps the
    // wallet's copy in sync for readers, it does not itself grant anything.
    receive(msg: RotateOwner) {
        throwUnless(38, self.extensions.get(sender()) == true);
        self.ownerPublicKey = msg.newOwnerPublicKey;
    }

    // Correlate first asset-hop bounces by the standard query ID and expected sender.
    bounced(body: Slice) {
        if (body.bits() < 96) { return; }
        body.loadUint(32);
        let requestId: Int = body.loadUint(64);
        if (self.destinations.get(requestId) != sender() || self.module == null) { return; }
        self.destinations.set(requestId, null);
        self.correlationCreatedAt.set(requestId, null);
        send(SendParameters{
            to: self.module!!, value: 0, mode: SendRemainingValue,
            body: WithdrawalFailed{ requestId: requestId }.toCell(),
        });
    }

    get fun protocolVersion(): Int { return 1; }
    get fun networkGlobalId(): Int { return self.networkGlobalId; }

    get fun seqno(): Int {
        return self.seqno;
    }

    get fun ownerPublicKey(): Int {
        return self.ownerPublicKey;
    }

    get fun isExtension(addr: Address): Bool {
        return self.extensions.get(addr) == true;
    }
}
