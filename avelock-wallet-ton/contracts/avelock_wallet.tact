// ============================================================
// Avelock Wallet
// Self-custody vault with on-chain withdrawal delays.
// https://github.com/avelock/AvelockWallet
// ============================================================
//
// AvelockWallet — TON port of the EVM AvelockWallet, same architecture as
// TON Wallet V5R1: a single owner public key authorizes external messages
// (signature + seqno replay protection), and an extension mechanism lets
// an authorized contract move funds via an internal message without any
// owner signature. This is the base wallet layer only — timelock,
// allowlist and duress logic attach later as a separate extension
// contract, exactly like the EVM version.

// Internal message sent by an authorized extension to move funds on the
// wallet's behalf. `sender()` in the receiver below is the TON-enforced,
// unspoofable source address of the internal message — the equivalent of
// EVM's `msg.sender` check in `executeFromExtension`.
message ExecuteFromExtension {
    to: Address;
    amount: Int as coins;
    body: Cell?;
}

// Owner-signed external message op codes, parsed inside external().
const OP_TRANSFER: Int = 1;
const OP_ADD_EXTENSION: Int = 2;
const OP_REMOVE_EXTENSION: Int = 3;

contract AvelockWallet {
    seqno: Int as uint32;
    ownerPublicKey: Int as uint256;
    extensions: map<Address, Bool>;

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

    // Single owner-signed external entry point (TON equivalent of the EVM
    // `execute()` path — offline-signed, relayable by anyone, authorized
    // purely by the ed25519 signature over the message body). An op
    // discriminant selects transfer vs. extension management, exactly
    // like the wallet exposing execute()/addExtension()/removeExtension()
    // as separate owner-only functions on EVM — here they all share one
    // signature-checked entry because that's how TON external messages
    // work.
    external(msg: Slice) {
        let signature: Slice = msg.loadBits(512);
        let signedHash: Int = msg.hash();
        throwUnless(35, checkSignature(signedHash, signature, self.ownerPublicKey));

        acceptMessage();

        let msgSeqno: Int = msg.loadUint(32);
        throwUnless(36, msgSeqno == self.seqno);
        self.seqno += 1;

        let validUntil: Int = msg.loadUint(32);
        throwUnless(37, validUntil == 0 || now() <= validUntil);

        let op: Int = msg.loadUint(8);

        if (op == OP_TRANSFER) {
            let to: Address = msg.loadAddress();
            let amount: Int = msg.loadCoins();
            let mode: Int = msg.loadUint(8);
            let body: Cell? = msg.loadMaybeRef();
            send(SendParameters{ to: to, value: amount, mode: mode, body: body });
        } else if (op == OP_ADD_EXTENSION) {
            let extension: Address = msg.loadAddress();
            self.extensions.set(extension, true);
        } else if (op == OP_REMOVE_EXTENSION) {
            let extension: Address = msg.loadAddress();
            self.extensions.set(extension, null);
        } else {
            throw(41);
        }

        commit();
    }

    // Extension calls funds movement without any owner signature — the
    // sole point where a future security module (timelock/allowlist)
    // attaches, exactly mirroring executeFromExtension() on the EVM side.
    // `sender()` here is set by the TON VM from the actual source
    // contract of the internal message and cannot be spoofed by the
    // sending contract, making this check equivalent to EVM's
    // `msg.sender == extensions[...]`.
    receive(msg: ExecuteFromExtension) {
        throwUnless(38, self.extensions.get(sender()) == true);
        send(SendParameters{ to: msg.to, value: msg.amount, mode: SendIgnoreErrors, body: msg.body });
    }

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
