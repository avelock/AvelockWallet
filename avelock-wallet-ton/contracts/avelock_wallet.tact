// ============================================================
// Avelock Wallet
// Self-custody vault with on-chain withdrawal delays.
// https://github.com/avelock/AvelockWallet
// ============================================================
//
// Protected TON vault. The signed owner entry point installs one permanent
// security module; all asset movements must subsequently come from that module.
// Complete and verify bootstrap before depositing assets.

// Internal message sent by an authorized extension to move funds on the
// wallet's behalf. `sender()` in the receiver below is the TON-enforced,
// unspoofable source address of the internal message — the equivalent of
// EVM's `msg.sender` check in `executeFromExtension`.
message ExecuteFromExtension {
    requestId: Int as uint64;
    to: Address;
    amount: Int as coins;
    body: Cell?;
}

// Owner-signed external message op codes, parsed inside external().
const OP_TRANSFER: Int = 1;
const OP_ADD_EXTENSION: Int = 2;
const OP_REMOVE_EXTENSION: Int = 3;

message WithdrawalFailed {
    requestId: Int as uint64;
}

contract AvelockWallet {
    seqno: Int as uint32;
    ownerPublicKey: Int as uint256;
    extensions: map<Address, Bool>;
    initialized: Bool = false;
    destinations: map<Int as uint64, Address>;
    module: Address?;

    init(ownerPublicKey: Int) {
        self.seqno = 0;
        self.ownerPublicKey = ownerPublicKey;
    }

    // Accept plain TON transfers with no restriction — incoming funds are
    // never subject to a delay (mirrors receive() on the EVM side). TON
    // credits the contract's balance automatically; this handler simply
    // needs to exist and do nothing, since cashback()/reject would send
    // the deposit straight back to the sender instead of keeping it.
    receive() {}

    // Domain-bound, expiring one-time bootstrap.
    external(msg: Slice) {
        let signature: Slice = msg.loadBits(512);
        let payload: Slice = msg.loadRef().beginParse();
        throwUnless(35, checkSignature(payload.hash(), signature, self.ownerPublicKey));
        throwUnless(39, payload.loadAddress() == myAddress());
        throwUnless(36, payload.loadUint(32) == self.seqno);
        let validUntil: Int = payload.loadUint(32);
        throwUnless(37, validUntil > 0 && now() <= validUntil && validUntil <= now() + 3600);
        // Bootstrap only: no direct transfer, removal or replacement operation exists.
        throwUnless(41, payload.loadUint(8) == OP_ADD_EXTENSION && !self.initialized);
        let extension: Address = payload.loadAddress();
        throwUnless(41, extension != myAddress());
        acceptMessage();
        self.seqno += 1;
        self.extensions.set(extension, true);
        self.initialized = true;
        self.module = extension;
    }

    // Only the installed security module may request a transfer.
    receive(msg: ExecuteFromExtension) {
        throwUnless(38, self.extensions.get(sender()) == true);
        self.destinations.set(msg.requestId, msg.to);
        let body: Cell? = msg.body;
        if (body == null) {
            body = beginCell().storeUint(0, 32).storeUint(msg.requestId, 64).endCell();
        }
        send(SendParameters{ to: msg.to, value: msg.amount, mode: SendPayGasSeparately | SendBounceIfActionFail, body: body });
    }

    // Correlate first asset-hop bounces by the standard query ID and expected sender.
    bounced(body: Slice) {
        if (body.bits() < 96) { return; }
        body.loadUint(32);
        let requestId: Int = body.loadUint(64);
        if (self.destinations.get(requestId) != sender() || self.module == null) { return; }
        self.destinations.set(requestId, null);
        send(SendParameters{
            to: self.module!!, value: 0, mode: SendRemainingValue,
            body: WithdrawalFailed{ requestId: requestId }.toCell(),
        });
    }

    get fun protocolVersion(): Int { return 2; }

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
