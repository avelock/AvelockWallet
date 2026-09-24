// Minimal TEP-62-shaped NFT item mock, for tests only. A real NFT item
// contract is a bit more involved (collection-linked, index tracking);
// this only needs to accept a transfer#5fcc3d14 message and update
// owner_address, enough to verify AvelockSecurityExtension builds the
// correct outbound message when withdrawing an NFT.

const NFT_TRANSFER_OP: Int = 0x5fcc3d14;

message(0x5fcc3d14) MockNftTransfer {
    queryId: Int as uint64;
    newOwner: Address;
    responseDestination: Address;
    customPayload: Cell?;
    forwardAmount: Int as coins;
}

contract MockNftItem {
    owner: Address;

    init(owner: Address) {
        self.owner = owner;
    }

    receive() {}

    receive(msg: MockNftTransfer) {
        throwUnless(70, sender() == self.owner);
        self.owner = msg.newOwner;
    }

    get fun owner(): Address {
        return self.owner;
    }
}
