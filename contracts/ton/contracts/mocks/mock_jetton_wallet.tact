// Minimal TEP-74-shaped jetton-wallet mock, for tests only. Real jetton
// wallets are far more involved (minter-linked, code-per-standard-impl);
// this only needs to accept a transfer#0f8a7ea5 message and track balance,
// enough to verify AvelockSecurityExtension builds the correct outbound
// message when withdrawing a jetton.

const JETTON_TRANSFER_OP: Int = 0x0f8a7ea5;

message(0x0f8a7ea5) MockJettonTransfer {
    queryId: Int as uint64;
    amount: Int as coins;
    destination: Address;
    responseDestination: Address;
    customPayload: Cell?;
    forwardTonAmount: Int as coins;
}

contract MockJettonWallet {
    balance: Int as coins;
    owner: Address;

    init(owner: Address, initialBalance: Int) {
        self.owner = owner;
        self.balance = initialBalance;
    }

    receive() {}

    receive(msg: MockJettonTransfer) {
        throwUnless(70, sender() == self.owner);
        throwUnless(71, self.balance >= msg.amount);
        self.balance -= msg.amount;
        // In a real jetton wallet this would credit the destination's own
        // jetton-wallet contract. For the test we just record the intent
        // via a bounceable no-op message so it's observable in the trace.
    }

    get fun balance(): Int {
        return self.balance;
    }
}
