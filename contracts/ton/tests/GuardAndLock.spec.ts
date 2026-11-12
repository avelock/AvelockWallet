import { Blockchain, SandboxContract, TreasuryContract } from '@ton/sandbox';
import { toNano, beginCell, Cell, Address, Dictionary } from '@ton/core';
import { keyPairFromSeed, sign } from '@ton/crypto';
import { AvelockSecurityExtension } from '../build/AvelockSecurityExtension/AvelockSecurityExtension_AvelockSecurityExtension';
import '@ton/test-utils';

// Guard keys and Panic Lock (FEATURE_PLANS.md, B1/B2).
const GLOBAL_ID = -3n;
const OP_ADD_ALLOWED_ADDRESS = 1;
const OP_REQUEST_WITHDRAWAL = 3;
const OP_CONFIRM_WITHDRAWAL = 5;
const OP_SET_POLICY_DELAY = 8;
const OP_ADD_GUARD = 18;
const OP_REMOVE_GUARD = 19;
const OP_FINALIZE_GUARD_REMOVAL = 21;
const OP_LOCK = 22;
const OP_UNLOCK = 23;
const OP_SET_LOCK_DELAY = 24;
const OP_SET_ADDRESS_DELAY = 7;
const OP_APPLY_PARAM_CHANGE = 9;
const OP_REGISTER_ASSET = 16;
const PARAM_ADDRESS_DELAY = 1;
const PARAM_POLICY_DELAY = 2;

const DAY = 24 * 60 * 60;
const WITHDRAWAL_DELAY = 3 * DAY;
const ADDRESS_DELAY = 2 * DAY;
const CONFIRMATION_WINDOW = DAY;
const POLICY_DELAY = 5 * DAY;
const MIN_DELAY = DAY;

describe('Guard keys and Panic Lock (TON)', () => {
    let blockchain: Blockchain;
    let deployer: SandboxContract<TreasuryContract>;
    let guard: SandboxContract<TreasuryContract>;
    let stranger: SandboxContract<TreasuryContract>;
    let recipient: SandboxContract<TreasuryContract>;
    let ext: SandboxContract<AvelockSecurityExtension>;
    let secretKey: Buffer;
    let seqno = 0;
    const now = () => blockchain.now ?? Math.floor(Date.now() / 1000);
    const wait = (s: number) => { blockchain.now = now() + s; };

    async function op(code: number, payload: (b: ReturnType<typeof beginCell>) => void = () => {}, tail: (b: ReturnType<typeof beginCell>) => void = () => {}) {
        const b = beginCell().storeAddress(ext.address).storeInt(GLOBAL_ID, 32).storeUint(seqno, 32).storeUint(now() + 600, 32).storeUint(code, 8);
        payload(b);
        if (code === OP_REQUEST_WITHDRAWAL) b.storeMaybeRef(null).storeBit(true);
        tail(b);
        const unsigned: Cell = b.endCell();
        seqno++;
        const body = beginCell().storeBuffer(sign(unsigned.hash(), secretKey)).storeRef(unsigned).endCell();
        await ext.sendExternal(body.asSlice());
        return { hash: unsigned.hash(), failed: async () => (await ext.getLastFailedOperationHash()) === BigInt('0x' + unsigned.hash().toString('hex')) };
    }
    const request = (to: Address) => op(OP_REQUEST_WITHDRAWAL, b => b.storeAddress(to).storeCoins(toNano('1')).storeUint(0, 2));

    beforeEach(async () => {
        blockchain = await Blockchain.create();
        const config = Dictionary.loadDirect(Dictionary.Keys.Int(32), Dictionary.Values.Cell(), blockchain.config);
        config.set(19, beginCell().storeInt(GLOBAL_ID, 32).endCell());
        blockchain.setConfig(beginCell().storeDictDirect(config).endCell());
        blockchain.now = Math.floor(Date.now() / 1000);
        const keys = keyPairFromSeed(Buffer.from('guard-lock-owner'.padEnd(32, '0')));
        secretKey = keys.secretKey;
        seqno = 0;
        deployer = await blockchain.treasury('deployer');
        guard = await blockchain.treasury('guard');
        stranger = await blockchain.treasury('stranger');
        recipient = await blockchain.treasury('recipient');
        const wallet = (await blockchain.treasury('wallet-placeholder')).address;
        ext = blockchain.openContract(await AvelockSecurityExtension.fromInit(
            BigInt('0x' + keys.publicKey.toString('hex')), GLOBAL_ID, wallet,
            BigInt(WITHDRAWAL_DELAY), BigInt(ADDRESS_DELAY), BigInt(CONFIRMATION_WINDOW), BigInt(POLICY_DELAY), BigInt(MIN_DELAY), BigInt(MIN_DELAY),
        ));
        await ext.send(deployer.getSender(), { value: toNano('0.05') }, null);
        await deployer.send({ to: ext.address, value: toNano('5') });
        await op(OP_ADD_ALLOWED_ADDRESS, b => b.storeAddress(recipient.address));
        await op(OP_ADD_GUARD, b => b.storeAddress(guard.address));
        wait(ADDRESS_DELAY + 1);
    });

    it('marks the feature and defaults the lock delay to a week', async () => {
        expect(await ext.getFeatures()).toBe(1n);
        expect(await ext.getLockDelay()).toBe(BigInt(7 * DAY));
        expect(await ext.getIsGuard(guard.address)).toBe(true);
    });

    it('a new guard waits the address delay; strangers are refused', async () => {
        await op(OP_ADD_GUARD, b => b.storeAddress(stranger.address));
        expect(await ext.getIsGuard(stranger.address)).toBe(false);
        const r = await ext.send(stranger.getSender(), { value: toNano('0.05') }, { $$type: 'GuardLock' });
        expect(r.transactions).toHaveTransaction({ to: ext.address, success: false, exitCode: 76 });
        expect(await ext.getLocked()).toBe(false);
    });

    it('at most two guards', async () => {
        await op(OP_ADD_GUARD, b => b.storeAddress(stranger.address));
        const third = await op(OP_ADD_GUARD, b => b.storeAddress(recipient.address));
        expect(await third.failed()).toBe(true);
        expect(await ext.getLastFailureCode()).toBe(74n);
    });

    it('a guard cancels a withdrawal with its own wallet and fees', async () => {
        await request(recipient.address);
        const r = await ext.send(guard.getSender(), { value: toNano('0.05') }, { $$type: 'GuardCancelWithdrawal', requestId: 0n });
        expect(r.transactions).toHaveTransaction({ from: guard.address, to: ext.address, success: true });
        expect((await ext.getRequest(0n))?.cancelled).toBe(true);
    });

    it('a guard cancels a queued setting change and a pending destination', async () => {
        await op(OP_SET_POLICY_DELAY, b => b.storeUint(POLICY_DELAY + DAY, 32));
        await op(OP_ADD_ALLOWED_ADDRESS, b => b.storeAddress(stranger.address));
        await ext.send(guard.getSender(), { value: toNano('0.05') }, { $$type: 'GuardCancelParamChange', param: BigInt(PARAM_POLICY_DELAY) });
        await ext.send(guard.getSender(), { value: toNano('0.05') }, { $$type: 'GuardCancelPendingAddress', destination: stranger.address });
        expect(await ext.getPendingParamChange(BigInt(PARAM_POLICY_DELAY))).toBeNull();
        expect(await ext.getAddressActiveAt(stranger.address)).toBe(0n);
        // An active destination is not the guard's to remove.
        const r = await ext.send(guard.getSender(), { value: toNano('0.05') }, { $$type: 'GuardCancelPendingAddress', destination: recipient.address });
        expect(r.transactions).toHaveTransaction({ to: ext.address, success: false, exitCode: 75 });
    });

    it('a guard lock voids pending requests and blocks new ones and confirmations', async () => {
        await request(recipient.address);
        await ext.send(guard.getSender(), { value: toNano('0.05') }, { $$type: 'GuardLock' });
        expect(await ext.getLocked()).toBe(true);
        expect(await ext.getIsRequestAnnulled(0n)).toBe(true);
        wait(WITHDRAWAL_DELAY + 1);
        const confirm = await op(OP_CONFIRM_WITHDRAWAL, b => b.storeUint(0, 64));
        expect(await confirm.failed()).toBe(true);
        expect(await ext.getLastFailureCode()).toBe(71n);
        const again = await request(recipient.address);
        expect(await again.failed()).toBe(true);
    });

    it('unlock waits the lock delay; a request from before the lock stays void', async () => {
        await request(recipient.address);
        await op(OP_LOCK);
        const early = await op(OP_UNLOCK);
        expect(await early.failed()).toBe(true);
        expect(await ext.getLastFailureCode()).toBe(73n);
        wait(7 * DAY);
        await op(OP_UNLOCK);
        expect(await ext.getLocked()).toBe(false);
        const old = await op(OP_CONFIRM_WITHDRAWAL, b => b.storeUint(0, 64));
        expect(await old.failed()).toBe(true);
        expect(await ext.getLastFailureCode()).toBe(72n);
        await request(recipient.address);
        wait(WITHDRAWAL_DELAY + 1);
        const fresh = await op(OP_CONFIRM_WITHDRAWAL, b => b.storeUint(1, 64));
        expect(await fresh.failed()).toBe(false);
        expect((await ext.getRequest(1n))?.submitted).toBe(true);
    });

    it('locking again extends the wait', async () => {
        await op(OP_LOCK);
        const first = await ext.getUnlockAfter();
        wait(3 * DAY);
        await ext.send(guard.getSender(), { value: toNano('0.05') }, { $$type: 'GuardLock' });
        expect(await ext.getUnlockAfter()).toBe(first + BigInt(3 * DAY));
        expect(await ext.getLockEpoch()).toBe(1n);
    });

    it('a lock voids a destination that was still waiting; adding it again waits again', async () => {
        await op(OP_ADD_ALLOWED_ADDRESS, b => b.storeAddress(stranger.address));
        await op(OP_LOCK);
        wait(7 * DAY);
        expect(await ext.getIsAddressActive(stranger.address)).toBe(false);
        expect(await ext.getIsAddressActive(recipient.address)).toBe(true);
        expect(await ext.getAddressActiveAt(stranger.address)).toBe(0n); // round2 M-2
        await op(OP_UNLOCK);
        await op(OP_ADD_ALLOWED_ADDRESS, b => b.storeAddress(stranger.address));
        expect(await ext.getIsAddressActive(stranger.address)).toBe(false);
        wait(ADDRESS_DELAY + 1);
        expect(await ext.getIsAddressActive(stranger.address)).toBe(true);
    });

    it('a lock drops pending guards and queued changes', async () => {
        await op(OP_ADD_GUARD, b => b.storeAddress(stranger.address));
        await op(OP_SET_POLICY_DELAY, b => b.storeUint(POLICY_DELAY + DAY, 32));
        await op(OP_LOCK);
        expect(await ext.getPendingParamChange(BigInt(PARAM_POLICY_DELAY))).toBeNull();
        wait(ADDRESS_DELAY + 1);
        expect(await ext.getIsGuard(stranger.address)).toBe(false);
        expect(await ext.getIsGuard(guard.address)).toBe(true);
    });

    const removalWait = async () => {
        const w = await ext.getWithdrawalDelay();
        const p = await ext.getPolicyDelay();
        return Number(p > w ? p : w) + Number(await ext.getLockDelay());
    };

    it('removing an active guard waits changeWait + lockDelay and the guard cannot stop it (MEGA_AUDIT ton_02 F1)', async () => {
        await op(OP_REMOVE_GUARD, b => b.storeAddress(guard.address));
        expect(await ext.getIsGuard(guard.address)).toBe(true);
        const total = await removalWait();
        wait(total - 10);
        const early = await op(OP_FINALIZE_GUARD_REMOVAL, b => b.storeAddress(guard.address));
        expect(await early.failed()).toBe(true);
        wait(20);
        await op(OP_FINALIZE_GUARD_REMOVAL, b => b.storeAddress(guard.address));
        expect(await ext.getIsGuard(guard.address)).toBe(false);
    });

    it('a rogue guard re-locking cannot keep itself in place (MEGA_AUDIT ton_02 F1)', async () => {
        await ext.send(guard.getSender(), { value: toNano('0.05') }, { $$type: 'GuardLock' });
        await op(OP_REMOVE_GUARD, b => b.storeAddress(guard.address)); // allowed while locked
        const again = await op(OP_REMOVE_GUARD, b => b.storeAddress(guard.address));
        expect(await again.failed()).toBe(true); // already queued
        const total = await removalWait();
        for (let k = 0; k < 3; k++) {
            wait(Math.floor(total / 3));
            await ext.send(guard.getSender(), { value: toNano('0.05') }, { $$type: 'GuardLock' });
        }
        wait(10);
        await op(OP_FINALIZE_GUARD_REMOVAL, b => b.storeAddress(guard.address)); // while locked
        expect(await ext.getLocked()).toBe(true);
        expect(await ext.getIsGuard(guard.address)).toBe(false);
    });

    it('a guard drops a guard that is still waiting', async () => {
        await op(OP_ADD_GUARD, b => b.storeAddress(stranger.address));
        await ext.send(guard.getSender(), { value: toNano('0.05') }, { $$type: 'GuardDropPendingGuard', guard: stranger.address });
        wait(ADDRESS_DELAY + 1);
        expect(await ext.getIsGuard(stranger.address)).toBe(false);
    });

    it('the lock delay never goes below the withdrawal floor', async () => {
        const low = await op(OP_SET_LOCK_DELAY, b => b.storeUint(MIN_DELAY - 1, 32));
        expect(await low.failed()).toBe(true);
        expect(await ext.getLastFailureCode()).toBe(56n);
    });

    it('a guard cancels an asset registration that is still waiting (round2 L-3)', async () => {
        const item = stranger.address;
        await op(OP_REGISTER_ASSET, b => b.storeAddress(item).storeUint(2, 2).storeRef(beginCell().storeAddress(recipient.address).endCell()));
        expect(await ext.getAssetRegistration(item)).not.toBeNull();
        await ext.send(guard.getSender(), { value: toNano('0.05') }, { $$type: 'GuardCancelPendingAsset', asset: item });
        expect(await ext.getAssetRegistration(item)).toBeNull();
        const r = await ext.send(stranger.getSender(), { value: toNano('0.05') }, { $$type: 'GuardCancelPendingAsset', asset: item });
        expect(r.transactions).toHaveTransaction({ to: ext.address, success: false, exitCode: 76 });
    });

    it('keeps the result of each recent operation by seqno (round2 L-4)', async () => {
        const first = seqno;
        await op(OP_LOCK);
        await op(OP_UNLOCK); // too early: fails
        expect(await ext.getOperationResult(BigInt(first))).toBe(0n);
        expect(await ext.getOperationResult(BigInt(first + 1))).toBe(73n);
        for (let i = 0; i < 8; i++) await op(OP_LOCK);
        expect(await ext.getOperationResult(BigInt(first))).toBeNull();
    });

    it('a request may carry a larger asset hop budget, capped at 0.3 TON (round2 L-2)', async () => {
        const id = (await ext.getNextRequestId?.()) ?? 0n;
        await op(OP_REQUEST_WITHDRAWAL, b => b.storeAddress(recipient.address).storeCoins(toNano('1')).storeUint(0, 2), b => b.storeCoins(toNano('0.2')));
        expect((await ext.getRequest(id))?.hopValue).toBe(toNano('0.2'));
        const tooMuch = await op(OP_REQUEST_WITHDRAWAL, b => b.storeAddress(recipient.address).storeCoins(toNano('1')).storeUint(0, 2), b => b.storeCoins(toNano('0.4')));
        expect(await tooMuch.failed()).toBe(true);
        const plain = await request(recipient.address);
        expect(await plain.failed()).toBe(false);
    });

    it('lowering the address delay waits at least the current address delay (round2 M-1)', async () => {
        await op(OP_SET_ADDRESS_DELAY, b => b.storeUint(10 * DAY, 32));
        wait(POLICY_DELAY + 1);
        await op(OP_APPLY_PARAM_CHANGE, b => b.storeUint(PARAM_ADDRESS_DELAY, 8));
        expect(await ext.getAddressDelay()).toBe(BigInt(10 * DAY));
        await op(OP_SET_ADDRESS_DELAY, b => b.storeUint(DAY, 32));
        const pending = await ext.getPendingParamChange(BigInt(PARAM_ADDRESS_DELAY));
        expect(Number(pending!.effectiveAt)).toBeGreaterThanOrEqual(now() + 10 * DAY);
    });

});
