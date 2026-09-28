import { Blockchain, SandboxContract, TreasuryContract } from '@ton/sandbox';
import { toNano, beginCell, Cell, Address, Dictionary } from '@ton/core';
import { keyPairFromSeed, sign } from '@ton/crypto';
import { AvelockWallet } from '../build/AvelockWallet/AvelockWallet_AvelockWallet';
import { AvelockSecurityExtension } from '../build/AvelockSecurityExtension/AvelockSecurityExtension_AvelockSecurityExtension';
import { MockJettonWallet } from '../build/MockJettonWallet/MockJettonWallet_MockJettonWallet';
import { MockNftItem } from '../build/MockNftItem/MockNftItem_MockNftItem';
import '@ton/test-utils';

const GLOBAL_ID = -3n;

const OP_ADD_ALLOWED_ADDRESS = 1;
const OP_REMOVE_ALLOWED_ADDRESS = 2;
const OP_REQUEST_WITHDRAWAL = 3;
const OP_CANCEL_WITHDRAWAL = 4;
const OP_CONFIRM_WITHDRAWAL = 5;
const OP_SET_WITHDRAWAL_DELAY = 6;
const OP_SET_ADDRESS_DELAY = 7;
const OP_SET_POLICY_DELAY = 8;
const OP_APPLY_PARAM_CHANGE = 9;
const OP_CANCEL_PARAM_CHANGE = 10;

const PARAM_WITHDRAWAL_DELAY = 0;
const PARAM_ADDRESS_DELAY = 1;
const PARAM_POLICY_DELAY = 2;

function seed(tag: string): Buffer {
    return Buffer.from(tag.padEnd(32, '0').slice(0, 32));
}

async function withGlobalId(): Promise<Blockchain> {
    const blockchain = await Blockchain.create();
    const config = Dictionary.loadDirect(Dictionary.Keys.Int(32), Dictionary.Values.Cell(), blockchain.config);
    config.set(19, beginCell().storeInt(GLOBAL_ID, 32).endCell());
    blockchain.setConfig(beginCell().storeDictDirect(config).endCell());
    return blockchain;
}

let signingAddress: Address;
let signingNow: () => number;

// Set by a payload writer that already stored its own comment field.
let commentWritten = false;
let bounceWritten = false;
function withBounce(b: ReturnType<typeof beginCell>, bounceable: boolean) {
    if (!commentWritten) { b.storeMaybeRef(null); commentWritten = true; }
    b.storeBit(bounceable);
    bounceWritten = true;
}
function withComment(b: ReturnType<typeof beginCell>, text: string) {
    b.storeMaybeRef(beginCell().storeUint(0, 32).storeStringTail(text).endCell());
    commentWritten = true;
}

function buildExternalBody(
    secretKey: Buffer,
    seqno: number,
    op: number,
    payload: (b: ReturnType<typeof beginCell>) => void,
): Cell {
    const unsigned = beginCell().storeAddress(signingAddress).storeInt(GLOBAL_ID, 32).storeUint(seqno, 32).storeUint(signingNow() + 600, 32).storeUint(op, 8);
    payload(unsigned);
    // Requests end with an optional comment reference and a bounce flag;
    // defaults (no comment, bounceable) unless the payload writer set them.
    if (op === OP_REQUEST_WITHDRAWAL) {
        if (!commentWritten) unsigned.storeMaybeRef(null);
        if (!bounceWritten) unsigned.storeBit(true);
    }
    commentWritten = false;
    bounceWritten = false;
    const unsignedCell = unsigned.endCell();
    const signature = sign(unsignedCell.hash(), secretKey);
    return beginCell().storeBuffer(signature).storeRef(unsignedCell).endCell();
}

// ---------------------------------------------------------------
// Extension-only state machine: allowlist/delay/policy logic in
// isolation, with freely chosen (non-fixed) delays. The "wallet" here
// is an untrusted placeholder address — these tests never rely on a
// successful extension -> wallet -> asset hop, only on the extension's
// own request/allowlist/policy bookkeeping.
// ---------------------------------------------------------------
describe('AvelockSecurityExtension (state machine)', () => {
    let blockchain: Blockchain;
    let deployer: SandboxContract<TreasuryContract>;
    let ext: SandboxContract<AvelockSecurityExtension>;
    let ownerSecretKey: Buffer;
    let ownerPublicKey: bigint;
    let walletPlaceholder: Address;

    const WITHDRAWAL_DELAY = 3 * 24 * 60 * 60;
    const ADDRESS_DELAY = 7 * 24 * 60 * 60;
    const CONFIRMATION_WINDOW = 1 * 24 * 60 * 60;
    const POLICY_DELAY = 5 * 24 * 60 * 60;
    const MIN_WITHDRAWAL_DELAY = 1 * 24 * 60 * 60;
    const MIN_ADDRESS_DELAY = 1 * 24 * 60 * 60;

    beforeEach(async () => {
        blockchain = await withGlobalId();
        const keyPair = keyPairFromSeed(seed('owner-seed'));
        ownerSecretKey = keyPair.secretKey;
        ownerPublicKey = BigInt('0x' + keyPair.publicKey.toString('hex'));
        deployer = await blockchain.treasury('deployer');
        walletPlaceholder = (await blockchain.treasury('wallet-placeholder')).address;

        ext = blockchain.openContract(
            await AvelockSecurityExtension.fromInit(
                ownerPublicKey,
                GLOBAL_ID,
                walletPlaceholder,
                BigInt(WITHDRAWAL_DELAY),
                BigInt(ADDRESS_DELAY),
                BigInt(CONFIRMATION_WINDOW),
                BigInt(POLICY_DELAY),
                BigInt(MIN_WITHDRAWAL_DELAY),
                BigInt(MIN_ADDRESS_DELAY),
            ),
        );
        await ext.send(deployer.getSender(), { value: toNano('0.05') }, null);
        await deployer.send({ to: ext.address, value: toNano('5') });

        signingAddress = ext.address;
        signingNow = () => blockchain.now ?? Math.floor(Date.now() / 1000);
    });

    it('deploys with correct immutable config', async () => {
        expect(await ext.getWithdrawalDelay()).toBe(BigInt(WITHDRAWAL_DELAY));
        expect(await ext.getAddressDelay()).toBe(BigInt(ADDRESS_DELAY));
        expect(await ext.getMinWithdrawalDelay()).toBe(BigInt(MIN_WITHDRAWAL_DELAY));
        expect(await ext.getMinAddressDelay()).toBe(BigInt(MIN_ADDRESS_DELAY));
    });

    it('rejects deployment if initial delay is below its own minimum', async () => {
        // fromInit() only computes the address/state-init locally — init()
        // itself (and its throwUnless checks) runs on-chain only once the
        // first message actually deploys the contract, so we must assert
        // on that deploy transaction, not on fromInit() resolving.
        const badExt = blockchain.openContract(
            await AvelockSecurityExtension.fromInit(
                ownerPublicKey,
                GLOBAL_ID,
                walletPlaceholder,
                BigInt(MIN_WITHDRAWAL_DELAY - 1),
                BigInt(ADDRESS_DELAY),
                BigInt(CONFIRMATION_WINDOW),
                BigInt(POLICY_DELAY),
                BigInt(MIN_WITHDRAWAL_DELAY),
                BigInt(MIN_ADDRESS_DELAY),
            ),
        );
        const result = await badExt.send(deployer.getSender(), { value: toNano('0.05') }, null);
        expect(result.transactions).toHaveTransaction({
            to: badExt.address,
            success: false,
        });
    });

    it('a new destination is inactive until the address delay elapses', async () => {
        const recipient = await blockchain.treasury('recipient');

        const addBody = buildExternalBody(ownerSecretKey, 0, OP_ADD_ALLOWED_ADDRESS, (b) => {
            b.storeAddress(recipient.address);
        });
        await ext.sendExternal(addBody.asSlice());

        expect(await ext.getIsAddressActive(recipient.address)).toBe(false);

        blockchain.now = (blockchain.now ?? Math.floor(Date.now() / 1000)) + ADDRESS_DELAY + 1;
        expect(await ext.getIsAddressActive(recipient.address)).toBe(true);
    });

    it('requestWithdrawal is rejected for a destination that is not active', async () => {
        const recipient = await blockchain.treasury('recipient');
        const reqBody = buildExternalBody(ownerSecretKey, 0, OP_REQUEST_WITHDRAWAL, (b) => {
            b.storeAddress(recipient.address).storeCoins(toNano('1')).storeUint(0, 2);
        });

        const result = await ext.sendExternal(reqBody.asSlice());
        expect(result.transactions).toHaveTransaction({ to: ext.address, success: true }); expect(await ext.getLastFailureCode()).not.toBe(0n);
    });

    async function allowAndActivate(addr: Address, seqnoStart: number): Promise<number> {
        const addBody = buildExternalBody(ownerSecretKey, seqnoStart, OP_ADD_ALLOWED_ADDRESS, (b) => {
            b.storeAddress(addr);
        });
        await ext.sendExternal(addBody.asSlice());
        blockchain.now = (blockchain.now ?? Math.floor(Date.now() / 1000)) + ADDRESS_DELAY + 1;
        return seqnoStart + 1;
    }

    it('cancel works before execution and blocks a later confirm', async () => {
        const recipient = await blockchain.treasury('recipient');
        let sq = await allowAndActivate(recipient.address, 0);

        const reqBody = buildExternalBody(ownerSecretKey, sq, OP_REQUEST_WITHDRAWAL, (b) => {
            b.storeAddress(recipient.address).storeCoins(toNano('1')).storeUint(0, 2);
        });
        await ext.sendExternal(reqBody.asSlice());
        sq += 1;

        const cancelBody = buildExternalBody(ownerSecretKey, sq, OP_CANCEL_WITHDRAWAL, (b) => {
            b.storeUint(0, 64);
        });
        await ext.sendExternal(cancelBody.asSlice());
        sq += 1;

        blockchain.now = (blockchain.now ?? Math.floor(Date.now() / 1000)) + WITHDRAWAL_DELAY + 1;
        const confirmBody = buildExternalBody(ownerSecretKey, sq, OP_CONFIRM_WITHDRAWAL, (b) => {
            b.storeUint(0, 64);
        });
        const result = await ext.sendExternal(confirmBody.asSlice());
        expect(result.transactions).toHaveTransaction({ to: ext.address, success: true }); expect(await ext.getLastFailureCode()).not.toBe(0n);
    });

    it('increasing a delay waits for the current policy delay', async () => {
        const setBody = buildExternalBody(ownerSecretKey, 0, OP_SET_WITHDRAWAL_DELAY, (b) => {
            b.storeUint(WITHDRAWAL_DELAY + 1000, 32);
        });
        await ext.sendExternal(setBody.asSlice());
        expect(await ext.getWithdrawalDelay()).toBe(BigInt(WITHDRAWAL_DELAY));
        const pending = await ext.getPendingParamChange(BigInt(PARAM_WITHDRAWAL_DELAY));
        expect(pending?.newValue).toBe(BigInt(WITHDRAWAL_DELAY + 1000));
    });

    it('raising the withdrawal delay past the lock delay raises the lock delay too (A12-3)', async () => {
        const longer = 30 * 86400;
        await ext.sendExternal(buildExternalBody(ownerSecretKey, 0, OP_SET_WITHDRAWAL_DELAY, (b) => { b.storeUint(longer, 32); }).asSlice());
        blockchain.now = (blockchain.now ?? Math.floor(Date.now() / 1000)) + POLICY_DELAY + 1;
        await ext.sendExternal(buildExternalBody(ownerSecretKey, 1, OP_APPLY_PARAM_CHANGE, (b) => { b.storeUint(PARAM_WITHDRAWAL_DELAY, 8); }).asSlice());
        expect(await ext.getWithdrawalDelay()).toBe(BigInt(longer));
        expect(await ext.getLockDelay()).toBe(BigInt(longer));
    });

    it('weakening a delay (decrease) queues instead of applying immediately, and needs the policy delay to elapse', async () => {
        const newValue = WITHDRAWAL_DELAY - 1000;
        const setBody = buildExternalBody(ownerSecretKey, 0, OP_SET_WITHDRAWAL_DELAY, (b) => {
            b.storeUint(newValue, 32);
        });
        await ext.sendExternal(setBody.asSlice());

        // Not applied yet.
        expect(await ext.getWithdrawalDelay()).toBe(BigInt(WITHDRAWAL_DELAY));

        const pending = await ext.getPendingParamChange(BigInt(PARAM_WITHDRAWAL_DELAY));
        expect(pending?.exists).toBe(true);
        expect(pending?.newValue).toBe(BigInt(newValue));

        // Too early to apply.
        const earlyApply = buildExternalBody(ownerSecretKey, 1, OP_APPLY_PARAM_CHANGE, (b) => {
            b.storeUint(PARAM_WITHDRAWAL_DELAY, 8);
        });
        const earlyResult = await ext.sendExternal(earlyApply.asSlice());
        expect(earlyResult.transactions).toHaveTransaction({ to: ext.address, success: true }); expect(await ext.getLastFailureCode()).not.toBe(0n);

        blockchain.now = (blockchain.now ?? Math.floor(Date.now() / 1000)) + POLICY_DELAY + 1;
        const applyBody = buildExternalBody(ownerSecretKey, 2, OP_APPLY_PARAM_CHANGE, (b) => {
            b.storeUint(PARAM_WITHDRAWAL_DELAY, 8);
        });
        await ext.sendExternal(applyBody.asSlice());
        expect(await ext.getWithdrawalDelay()).toBe(BigInt(newValue));
    });

    it('a short policy delay cannot lower the withdrawal delay sooner than the withdrawal delay (A14-2)', async () => {
        const at = () => blockchain.now ?? Math.floor(Date.now() / 1000);
        // Policy delay down to one hour: waits the current policy delay (5 days).
        await ext.sendExternal(buildExternalBody(ownerSecretKey, 0, OP_SET_POLICY_DELAY, (b) => { b.storeUint(3600, 32); }).asSlice());
        blockchain.now = at() + POLICY_DELAY + 1;
        await ext.sendExternal(buildExternalBody(ownerSecretKey, 1, OP_APPLY_PARAM_CHANGE, (b) => { b.storeUint(PARAM_POLICY_DELAY, 8); }).asSlice());
        expect(await ext.getPolicyDelay()).toBe(3600n);
        // Withdrawal delay down to the minimum: still waits the withdrawal delay, not one hour.
        await ext.sendExternal(buildExternalBody(ownerSecretKey, 2, OP_SET_WITHDRAWAL_DELAY, (b) => { b.storeUint(MIN_WITHDRAWAL_DELAY, 32); }).asSlice());
        blockchain.now = at() + 3600 + 1;
        await ext.sendExternal(buildExternalBody(ownerSecretKey, 3, OP_APPLY_PARAM_CHANGE, (b) => { b.storeUint(PARAM_WITHDRAWAL_DELAY, 8); }).asSlice());
        expect(await ext.getWithdrawalDelay()).toBe(BigInt(WITHDRAWAL_DELAY));
        blockchain.now = at() + WITHDRAWAL_DELAY;
        await ext.sendExternal(buildExternalBody(ownerSecretKey, 4, OP_APPLY_PARAM_CHANGE, (b) => { b.storeUint(PARAM_WITHDRAWAL_DELAY, 8); }).asSlice());
        expect(await ext.getWithdrawalDelay()).toBe(BigInt(MIN_WITHDRAWAL_DELAY));
    });

    it('rejects weakening a delay below its immutable minimum, even as a queued change', async () => {
        const setBody = buildExternalBody(ownerSecretKey, 0, OP_SET_WITHDRAWAL_DELAY, (b) => {
            b.storeUint(MIN_WITHDRAWAL_DELAY - 1, 32);
        });
        const result = await ext.sendExternal(setBody.asSlice());
        expect(result.transactions).toHaveTransaction({ to: ext.address, success: true }); expect(await ext.getLastFailureCode()).not.toBe(0n);

        const pending = await ext.getPendingParamChange(BigInt(PARAM_WITHDRAWAL_DELAY));
        expect(pending?.exists ?? false).toBe(false);
    });

    it('cancelParamChange removes a queued weakening before it applies', async () => {
        const setBody = buildExternalBody(ownerSecretKey, 0, OP_SET_WITHDRAWAL_DELAY, (b) => {
            b.storeUint(WITHDRAWAL_DELAY - 1000, 32);
        });
        await ext.sendExternal(setBody.asSlice());

        const cancelBody = buildExternalBody(ownerSecretKey, 1, OP_CANCEL_PARAM_CHANGE, (b) => {
            b.storeUint(PARAM_WITHDRAWAL_DELAY, 8);
        });
        await ext.sendExternal(cancelBody.asSlice());

        const pending = await ext.getPendingParamChange(BigInt(PARAM_WITHDRAWAL_DELAY));
        expect(pending?.exists ?? false).toBe(false);
    });

    it('re-setting the current value withdraws a queued change (AVL-TON-001)', async () => {
        await ext.sendExternal(buildExternalBody(ownerSecretKey, 0, OP_SET_WITHDRAWAL_DELAY, (b) => {
            b.storeUint(WITHDRAWAL_DELAY - 1000, 32);
        }).asSlice());
        expect((await ext.getPendingParamChange(BigInt(PARAM_WITHDRAWAL_DELAY)))?.exists ?? false).toBe(true);

        await ext.sendExternal(buildExternalBody(ownerSecretKey, 1, OP_SET_WITHDRAWAL_DELAY, (b) => {
            b.storeUint(WITHDRAWAL_DELAY, 32);
        }).asSlice());
        expect((await ext.getPendingParamChange(BigInt(PARAM_WITHDRAWAL_DELAY)))?.exists ?? false).toBe(false);
    });

    it('reports protocol version 1', async () => {
        expect(await ext.getProtocolVersion()).toBe(1n);
    });

    it('rejects parameters above fixed caps and queues a larger confirmation window', async () => {
        let sq = 0;
        for (const op of [6, 7, 8, 11]) {
            const cap = op === 11 ? 30 * 86400 : 90 * 86400;
            const result = await ext.sendExternal(buildExternalBody(ownerSecretKey, sq++, op, b => b.storeUint(cap + 1, 32)).asSlice());
            expect(result.transactions).toHaveTransaction({ to: ext.address, success: true }); expect(await ext.getLastFailureCode()).not.toBe(0n);
            // A failed op still consumes its nonce, so it can't be replayed.
            expect(await ext.getSeqno()).toBe(BigInt(sq));
        }
        await ext.sendExternal(buildExternalBody(ownerSecretKey, sq, 11, b => b.storeUint(2 * 86400, 32)).asSlice());
        expect(await ext.getConfirmationWindow()).toBe(BigInt(CONFIRMATION_WINDOW));
        expect((await ext.getPendingParamChange(3n))?.newValue).toBe(172800n);
    });

    it('a failed signed op consumes its seqno and cannot be replayed to drain gas', async () => {
        const target = await blockchain.treasury('replay-target');
        // Not allowlisted -> the request fails after acceptMessage().
        const body = buildExternalBody(ownerSecretKey, 0, OP_REQUEST_WITHDRAWAL,
            b => b.storeAddress(target.address).storeCoins(1).storeUint(0, 2)).asSlice();
        const first = await ext.sendExternal(body);
        expect(first.transactions).toHaveTransaction({ to: ext.address, success: true });
        expect(await ext.getLastFailureCode()).toBe(52n);
        expect(await ext.getSeqno()).toBe(1n);
        expect(await ext.getNextRequestId()).toBe(0n);
        await expect(ext.sendExternal(body)).rejects.toBeDefined();
    });

    it('requires contract-bound expiring signatures before accepting external messages', async () => {
        const target = await blockchain.treasury('target');
        for (const [domain, deadline] of [[walletPlaceholder, signingNow() + 600], [ext.address, 0], [ext.address, 1]] as const) {
            const payload = beginCell().storeAddress(domain).storeInt(GLOBAL_ID, 32).storeUint(0, 32).storeUint(deadline, 32)
                .storeUint(OP_ADD_ALLOWED_ADDRESS, 8).storeAddress(target.address).endCell();
            const body = beginCell().storeBuffer(sign(payload.hash(), ownerSecretKey)).storeRef(payload).endCell();
            await expect(ext.sendExternal(body.asSlice())).rejects.toBeDefined();
        }
        expect(await ext.getSeqno()).toBe(0n);
    });

    it('requires separate asset registration for contracts receiving TON fees', async () => {
        const target = await blockchain.treasury('target');
        const asset = await blockchain.treasury('asset');
        let sq = await allowAndActivate(target.address, 0);
        for (const kind of [1, 2]) {
            const result = await ext.sendExternal(buildExternalBody(ownerSecretKey, sq++, OP_REQUEST_WITHDRAWAL,
                b => b.storeAddress(target.address).storeCoins(1).storeUint(kind, 2)
                    .storeRef(beginCell().storeAddress(asset.address))).asSlice());
            expect(result.transactions).toHaveTransaction({ to: ext.address, success: true }); expect(await ext.getLastFailureCode()).not.toBe(0n);
        }
        expect(await ext.getNextRequestId()).toBe(0n);
    });
});

// ---------------------------------------------------------------
// Withdrawal execution integration: the extension deployed exactly as
// AvelockWallet's constructor deploys its own trusted module (fixed
// delays, same params), so confirmWithdrawal's extension -> wallet ->
// asset hop is authorized end to end.
// ---------------------------------------------------------------
describe('AvelockSecurityExtension (withdrawal execution)', () => {
    let blockchain: Blockchain;
    let deployer: SandboxContract<TreasuryContract>;
    let wallet: SandboxContract<AvelockWallet>;
    let ext: SandboxContract<AvelockSecurityExtension>;
    let ownerSecretKey: Buffer;
    let ownerPublicKey: bigint;

    const WITHDRAWAL_DELAY = 86400;
    const ADDRESS_DELAY = 604800;

    beforeEach(async () => {
        blockchain = await withGlobalId();
        const keyPair = keyPairFromSeed(seed('owner-seed'));
        ownerSecretKey = keyPair.secretKey;
        ownerPublicKey = BigInt('0x' + keyPair.publicKey.toString('hex'));
        deployer = await blockchain.treasury('deployer');

        wallet = blockchain.openContract(await AvelockWallet.fromInit(
            ownerPublicKey, GLOBAL_ID,
            BigInt(WITHDRAWAL_DELAY), BigInt(ADDRESS_DELAY), BigInt(WITHDRAWAL_DELAY), BigInt(ADDRESS_DELAY),
            BigInt(WITHDRAWAL_DELAY), BigInt(WITHDRAWAL_DELAY),
        ));
        await wallet.send(deployer.getSender(), { value: toNano('1') }, null);
        await deployer.send({ to: wallet.address, value: toNano('50') });

        ext = blockchain.openContract(
            await AvelockSecurityExtension.fromInit(
                ownerPublicKey, GLOBAL_ID, wallet.address,
                BigInt(WITHDRAWAL_DELAY), BigInt(ADDRESS_DELAY), BigInt(WITHDRAWAL_DELAY), BigInt(ADDRESS_DELAY),
                BigInt(WITHDRAWAL_DELAY), BigInt(WITHDRAWAL_DELAY),
            ),
        );
        await ext.send(deployer.getSender(), { value: toNano('0.2') }, null);
        await deployer.send({ to: ext.address, value: toNano('5') });

        signingAddress = ext.address;
        signingNow = () => blockchain.now ?? Math.floor(Date.now() / 1000);

        expect(await wallet.getIsExtension(ext.address)).toBe(true);
    });

    async function allowAndActivate(addr: Address, seqnoStart: number): Promise<number> {
        const addBody = buildExternalBody(ownerSecretKey, seqnoStart, OP_ADD_ALLOWED_ADDRESS, (b) => {
            b.storeAddress(addr);
        });
        await ext.sendExternal(addBody.asSlice());
        blockchain.now = (blockchain.now ?? Math.floor(Date.now() / 1000)) + ADDRESS_DELAY + 1;
        return seqnoStart + 1;
    }

    async function registerAndActivate(asset: Address, kind: number, seqno: number) {
        await ext.sendExternal(buildExternalBody(ownerSecretKey, seqno, 16,
            b => b.storeAddress(asset).storeUint(kind, 2).storeRef(beginCell().storeAddress(wallet.address))).asSlice());
        blockchain.now = (blockchain.now ?? Math.floor(Date.now() / 1000)) + Math.max(Number(await ext.getPolicyDelay()), Number(await ext.getAddressDelay())) + 1;
        return seqno + 1;
    }

    it('full lifecycle: request -> too-early confirm rejected -> confirm succeeds after delay', async () => {
        const recipient = await blockchain.treasury('recipient');
        let sq = await allowAndActivate(recipient.address, 0);

        const reqBody = buildExternalBody(ownerSecretKey, sq, OP_REQUEST_WITHDRAWAL, (b) => {
            b.storeAddress(recipient.address).storeCoins(toNano('2')).storeUint(0, 2);
        });
        await ext.sendExternal(reqBody.asSlice());
        sq += 1;

        const req0 = await ext.getRequest(0n);
        expect(await ext.getRequestIdForOperation(BigInt(sq - 1))).toBe(0n);
        expect(req0?.submitted).toBe(false);

        // Too early — withdrawalDelay has not elapsed yet.
        const earlyConfirm = buildExternalBody(ownerSecretKey, sq, OP_CONFIRM_WITHDRAWAL, (b) => {
            b.storeUint(0, 64);
        });
        const earlyResult = await ext.sendExternal(earlyConfirm.asSlice());
        expect(earlyResult.transactions).toHaveTransaction({ to: ext.address, success: true }); expect(await ext.getLastFailureCode()).not.toBe(0n);

        // The failed attempt consumed its seqno; confirm with the next one.
        blockchain.now = (blockchain.now ?? Math.floor(Date.now() / 1000)) + WITHDRAWAL_DELAY + 1;

        const recipientBalanceBefore = (await blockchain.getContract(recipient.address)).balance;

        const confirmBody = buildExternalBody(ownerSecretKey, sq + 1, OP_CONFIRM_WITHDRAWAL, (b) => {
            b.storeUint(0, 64);
        });
        const confirmResult = await ext.sendExternal(confirmBody.asSlice());
        expect(confirmResult.transactions).toHaveTransaction({
            from: ext.address,
            to: wallet.address,
            success: true,
        });
        expect(confirmResult.transactions).toHaveTransaction({
            from: wallet.address,
            to: recipient.address,
            success: true,
        });

        const recipientBalanceAfter = (await blockchain.getContract(recipient.address)).balance;
        expect(recipientBalanceAfter).toBeGreaterThan(recipientBalanceBefore);

        const req0After = await ext.getRequest(0n);
        expect(req0After?.submitted).toBe(true);
    });

    it('confirmWithdrawal for a jetton sends a correctly-shaped TEP-74 transfer to the wallet\'s jetton-wallet contract', async () => {
        const recipient = await blockchain.treasury('recipient');
        let sq = await allowAndActivate(recipient.address, 0);

        const jettonWallet = blockchain.openContract(
            await MockJettonWallet.fromInit(wallet.address, toNano('1000')),
        );
        await jettonWallet.send(deployer.getSender(), { value: toNano('0.5') }, null);
        sq = await registerAndActivate(jettonWallet.address, 1, sq);

        const reqBody = buildExternalBody(ownerSecretKey, sq, OP_REQUEST_WITHDRAWAL, (b) => {
            b.storeAddress(recipient.address).storeCoins(toNano('50')).storeUint(1, 2).storeRef(beginCell().storeAddress(jettonWallet.address).endCell());
        });
        await ext.sendExternal(reqBody.asSlice());
        sq += 1;

        blockchain.now = (blockchain.now ?? Math.floor(Date.now() / 1000)) + WITHDRAWAL_DELAY + 1;

        const confirmBody = buildExternalBody(ownerSecretKey, sq, OP_CONFIRM_WITHDRAWAL, (b) => {
            b.storeUint(0, 64);
        });
        const result = await ext.sendExternal(confirmBody.asSlice());

        // extension -> wallet (ExecuteFromExtension) -> wallet's jetton
        // wallet (TEP-74 transfer) -> mock deducts balance.
        expect(result.transactions).toHaveTransaction({ from: ext.address, to: wallet.address, success: true });
        expect(result.transactions).toHaveTransaction({ from: wallet.address, to: jettonWallet.address, success: true });

        expect(await jettonWallet.getBalance()).toBe(toNano('950'));

        const req0 = await ext.getRequest(0n);
        expect(req0?.submitted).toBe(true);
    });

    function readComment(cell: Cell): string {
        const sl = cell.beginParse();
        expect(sl.loadUint(32)).toBe(0);
        return sl.loadStringTail();
    }

    it('native withdrawal delivers the requested text comment as the transfer body', async () => {
        const recipient = await blockchain.treasury('memo-recipient');
        let sq = await allowAndActivate(recipient.address, 0);
        await ext.sendExternal(buildExternalBody(ownerSecretKey, sq++, OP_REQUEST_WITHDRAWAL, (b) => {
            b.storeAddress(recipient.address).storeCoins(toNano('1')).storeUint(0, 2);
            withComment(b, 'MEMO 104729');
        }).asSlice());
        blockchain.now = (blockchain.now ?? Math.floor(Date.now() / 1000)) + WITHDRAWAL_DELAY + 1;
        const result = await ext.sendExternal(buildExternalBody(ownerSecretKey, sq, OP_CONFIRM_WITHDRAWAL, b => b.storeUint(0, 64)).asSlice());
        const delivered = result.transactions.find(t =>
            t.inMessage?.info.src?.toString() === wallet.address.toString() &&
            t.inMessage?.info.dest?.toString() === recipient.address.toString());
        expect(delivered).toBeDefined();
        expect(readComment(delivered!.inMessage!.body)).toBe('MEMO 104729');
    });

    it('jetton withdrawal carries the comment in forward_payload with a notification amount', async () => {
        const recipient = await blockchain.treasury('memo-recipient');
        let sq = await allowAndActivate(recipient.address, 0);
        const jettonWallet = blockchain.openContract(await MockJettonWallet.fromInit(wallet.address, toNano('1000')));
        await jettonWallet.send(deployer.getSender(), { value: toNano('0.5') }, null);
        sq = await registerAndActivate(jettonWallet.address, 1, sq);
        await ext.sendExternal(buildExternalBody(ownerSecretKey, sq++, OP_REQUEST_WITHDRAWAL, (b) => {
            b.storeAddress(recipient.address).storeCoins(toNano('5')).storeUint(1, 2)
                .storeRef(beginCell().storeAddress(jettonWallet.address).endCell());
            withComment(b, 'usdt-deposit-77');
        }).asSlice());
        blockchain.now = (blockchain.now ?? Math.floor(Date.now() / 1000)) + WITHDRAWAL_DELAY + 1;
        const result = await ext.sendExternal(buildExternalBody(ownerSecretKey, sq, OP_CONFIRM_WITHDRAWAL, b => b.storeUint(0, 64)).asSlice());
        const hop = result.transactions.find(t => t.inMessage?.info.dest?.toString() === jettonWallet.address.toString());
        const body = hop!.inMessage!.body.beginParse();
        expect(body.loadUint(32)).toBe(0x0f8a7ea5);
        body.loadUint(64); body.loadCoins(); body.loadAddress(); body.loadAddress();
        expect(body.loadBit()).toBe(false);          // no custom_payload
        expect(body.loadCoins()).toBeGreaterThan(0n); // forward_ton_amount
        expect(body.loadBit()).toBe(true);            // forward_payload by reference
        expect(readComment(body.loadRef())).toBe('usdt-deposit-77');
        expect(await jettonWallet.getBalance()).toBe(toNano('995'));
    });

    async function withdrawNativeTo(to: Address, bounceable: boolean) {
        let sq = await allowAndActivate(to, 0);
        await ext.sendExternal(buildExternalBody(ownerSecretKey, sq++, OP_REQUEST_WITHDRAWAL, (b) => {
            b.storeAddress(to).storeCoins(toNano('1')).storeUint(0, 2);
            withBounce(b, bounceable);
        }).asSlice());
        blockchain.now = (blockchain.now ?? Math.floor(Date.now() / 1000)) + WITHDRAWAL_DELAY + 1;
        return ext.sendExternal(buildExternalBody(ownerSecretKey, sq, OP_CONFIRM_WITHDRAWAL, b => b.storeUint(0, 64)).asSlice());
    }

    it('non-bounceable native withdrawal reaches a never-deployed wallet address', async () => {
        const fresh = new Address(0, Buffer.alloc(32, 0xab));
        await withdrawNativeTo(fresh, false);
        expect((await blockchain.getContract(fresh)).balance).toBe(toNano('1'));
        const req = await ext.getRequest(0n);
        expect(req?.submitted).toBe(true);
        expect(req?.failed).toBe(false);
    });

    it('bounceable native withdrawal to a never-deployed address still returns the TON (safe default)', async () => {
        const fresh = new Address(0, Buffer.alloc(32, 0xcd));
        const before = (await blockchain.getContract(wallet.address)).balance;
        const extBefore = (await blockchain.getContract(ext.address)).balance;
        await withdrawNativeTo(fresh, true);
        expect((await blockchain.getContract(fresh)).balance).toBe(0n);
        expect((await ext.getRequest(0n))?.failed).toBe(true);
        // The bounced TON stays in the Vault (minus small fees) and is not
        // forwarded to the security module along with the failure notice.
        expect((await blockchain.getContract(wallet.address)).balance).toBeGreaterThan(before - toNano('0.1'));
        expect((await blockchain.getContract(ext.address)).balance).toBeLessThan(extBefore);
    });

    it('rejects a non-bounceable flag for jetton/NFT withdrawals', async () => {
        const recipient = await blockchain.treasury('memo-recipient');
        const sq = await allowAndActivate(recipient.address, 0);
        const result = await ext.sendExternal(buildExternalBody(ownerSecretKey, sq, OP_REQUEST_WITHDRAWAL, (b) => {
            b.storeAddress(recipient.address).storeCoins(1).storeUint(1, 2)
                .storeRef(beginCell().storeAddress(recipient.address).endCell());
            withBounce(b, false);
        }).asSlice());
        expect((result).transactions).toHaveTransaction({to:ext.address,success:true}); expect(await ext.getLastFailureCode()).toBe(70n);
    });

    it('rejects a non-comment body or a multi-cell comment in a request', async () => {
        const recipient = await blockchain.treasury('memo-recipient');
        let sq = await allowAndActivate(recipient.address, 0);
        const bodies = [
            beginCell().storeUint(0x0f8a7ea5, 32).endCell(),                        // arbitrary opcode
            beginCell().storeUint(0, 32).storeRef(beginCell().endCell()).endCell(), // extra reference
            // Text whose first bytes read as a request id (audit M-2): its bounce
            // would otherwise mark request 0 as failed.
            beginCell().storeUint(0, 32).storeUint(0, 64).storeStringTail('x').endCell(),
        ];
        for (const bad of bodies) {
            const result = await ext.sendExternal(buildExternalBody(ownerSecretKey, sq++, OP_REQUEST_WITHDRAWAL, (b) => {
                b.storeAddress(recipient.address).storeCoins(toNano('1')).storeUint(0, 2).storeMaybeRef(bad);
                commentWritten = true;
            }).asSlice());
            expect((result).transactions).toHaveTransaction({to:ext.address,success:true}); expect(await ext.getLastFailureCode()).toBe(69n);
        }
        expect(await ext.getNextRequestId()).toBe(0n);
    });

    it('confirmWithdrawal for an NFT sends a correctly-shaped TEP-62 transfer to the item contract', async () => {
        const recipient = await blockchain.treasury('recipient');
        let sq = await allowAndActivate(recipient.address, 0);

        const nftItem = blockchain.openContract(await MockNftItem.fromInit(wallet.address));
        await nftItem.send(deployer.getSender(), { value: toNano('0.5') }, null);
        sq = await registerAndActivate(nftItem.address, 2, sq);

        // amount is irrelevant for an NFT withdrawal — the asset moved is
        // the item itself, not a coin quantity. assetKind=2 (ASSET_NFT).
        const reqBody = buildExternalBody(ownerSecretKey, sq, OP_REQUEST_WITHDRAWAL, (b) => {
            b.storeAddress(recipient.address)
                .storeCoins(0n)
                .storeUint(2, 2)
                .storeRef(beginCell().storeAddress(nftItem.address).endCell());
        });
        await ext.sendExternal(reqBody.asSlice());
        sq += 1;

        blockchain.now = (blockchain.now ?? Math.floor(Date.now() / 1000)) + WITHDRAWAL_DELAY + 1;

        const confirmBody = buildExternalBody(ownerSecretKey, sq, OP_CONFIRM_WITHDRAWAL, (b) => {
            b.storeUint(0, 64);
        });
        const result = await ext.sendExternal(confirmBody.asSlice());

        // extension -> wallet (ExecuteFromExtension) -> NFT item contract
        // (TEP-62 transfer) -> mock reassigns owner.
        expect(result.transactions).toHaveTransaction({ from: ext.address, to: wallet.address, success: true });
        expect(result.transactions).toHaveTransaction({ from: wallet.address, to: nftItem.address, success: true });

        expect((await nftItem.getOwner()).equals(recipient.address)).toBe(true);

        const req0 = await ext.getRequest(0n);
        expect(req0?.submitted).toBe(true);
    });

    it('rechecks the destination at confirmation', async () => {
        const target = await blockchain.treasury('target');
        let sq = await allowAndActivate(target.address, 0);
        await ext.sendExternal(buildExternalBody(ownerSecretKey, sq++, OP_REQUEST_WITHDRAWAL,
            b => b.storeAddress(target.address).storeCoins(toNano('1')).storeUint(0, 2)).asSlice());
        await ext.sendExternal(buildExternalBody(ownerSecretKey, sq++, OP_REMOVE_ALLOWED_ADDRESS,
            b => b.storeAddress(target.address)).asSlice());
        blockchain.now = signingNow() + WITHDRAWAL_DELAY;
        const result = await ext.sendExternal(buildExternalBody(ownerSecretKey, sq, OP_CONFIRM_WITHDRAWAL,
            b => b.storeUint(0, 64)).asSlice());
        expect(result.transactions).toHaveTransaction({ to: ext.address, success: true }); expect(await ext.getLastFailureCode()).not.toBe(0n);
        expect((await ext.getRequest(0n))?.submitted).toBe(false);
    });

    it('records a wallet action failure and permits retry only after the first-hop bounce', async () => {
        const target = await blockchain.treasury('target');
        let sq = await allowAndActivate(target.address, 0);
        await ext.sendExternal(buildExternalBody(ownerSecretKey, sq++, OP_REQUEST_WITHDRAWAL,
            b => b.storeAddress(target.address).storeCoins(toNano('100')).storeUint(0, 2)).asSlice());
        blockchain.now = signingNow() + WITHDRAWAL_DELAY;
        const result = await ext.sendExternal(buildExternalBody(ownerSecretKey, sq, OP_CONFIRM_WITHDRAWAL,
            b => b.storeUint(0, 64)).asSlice());
        expect(result.transactions).toHaveTransaction({ from: ext.address, to: wallet.address, success: false });
        const request = await ext.getRequest(0n);
        expect(request?.failed).toBe(true);
        expect(request?.submitted).toBe(false);
    });

    it('surfaces an asset-hop rejection without claiming settlement or enabling an automatic retry', async () => {
        const target = await blockchain.treasury('target');
        let sq = await allowAndActivate(target.address, 0);
        const jetton = blockchain.openContract(await MockJettonWallet.fromInit(wallet.address, 1n));
        await jetton.send(deployer.getSender(), { value: toNano('0.5') }, null);
        sq = await registerAndActivate(jetton.address, 1, sq);
        await ext.sendExternal(buildExternalBody(ownerSecretKey, sq++, OP_REQUEST_WITHDRAWAL,
            b => b.storeAddress(target.address).storeCoins(2).storeUint(1, 2)
                .storeRef(beginCell().storeAddress(jetton.address))).asSlice());
        blockchain.now = signingNow() + WITHDRAWAL_DELAY;
        const result = await ext.sendExternal(buildExternalBody(ownerSecretKey, sq, OP_CONFIRM_WITHDRAWAL,
            b => b.storeUint(0, 64)).asSlice());
        expect(result.transactions).toHaveTransaction({ from: wallet.address, to: jetton.address, success: false });
        const request = await ext.getRequest(0n);
        expect(request?.failed).toBe(true);
        expect(request?.submitted).toBe(true);
    });
});
