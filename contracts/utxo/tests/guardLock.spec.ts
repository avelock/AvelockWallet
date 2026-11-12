// Guard keys and Panic Lock at the signer (FEATURE_PLANS.md, B1/B2). No Bitcoin node needed.
import * as bitcoin from 'bitcoinjs-lib';
import * as ecc from '@bitcoinerlab/secp256k1';
import { ECPairFactory } from 'ecpair';
import * as bip39 from 'bip39';
import { taprootSigner } from '../src/keys';
import { ownerAccountXpub, ownerKey } from '../src/mnemonicKeys';
import { GuardOperation, operationDigest, Operation, Policy, signGuardOperation, signOperation, verifyWithdrawalIntent } from '../src/signer/messages';
import { REFRESH_INTERVAL, REFRESH_INTERVAL_LOCKED, SignerService } from '../src/signer/service';
import { createVault } from '../src/vault';
import { buildSpend, signSpend } from '../src/spend';

const network = bitcoin.networks.regtest;
const ECPair = ECPairFactory(ecc);
const DAY = 86400;
const policy: Policy = { withdrawalDelay: DAY, addressDelay: 2 * DAY, policyDelay: DAY, confirmationWindow: DAY, maxFee: 10_000 };
const destination = bitcoin.payments.p2tr({ internalPubkey: Buffer.alloc(32, 2), network }).address!;
const key = () => {
  const kp = ECPair.makeRandom({ network });
  return taprootSigner({ privateKey: kp.privateKey!, publicKey: Buffer.from(kp.publicKey) });
};
const other = bitcoin.payments.p2tr({ internalPubkey: key().publicKey, network }).address!;

function setup() {
  let clock = 1_800_000_000;
  const signer = new SignerService({ key: key(), network, networkName: 'regtest', now: () => clock, sendSos: () => {} });
  const mnemonic = bip39.generateMnemonic(256);
  const owner = ownerKey(mnemonic, network);
  const account = owner.publicKey.toString('hex');
  signer.submit(signOperation({
    domain: signer.domain, account, nonce: 0, expiresAt: clock + 600,
    operation: { op: 'register', accountXpub: ownerAccountXpub(mnemonic, network), policy,
      vault: { generation: 0, owner: account, signers: [signer.publicKey], threshold: 1, reserveBlocks: 52_560 },
      floors: { withdrawalDelay: 3600, addressDelay: 3600 } },
  }, owner));
  const op = (operation: Operation) => {
    const a = signer.getAccount(account)!;
    return signer.submit(signOperation({ domain: signer.domain, account, nonce: a.nonce, expiresAt: clock + 600, head: a.head.hash, operation }, owner)) as any;
  };
  const guardKey = key();
  const guard = guardKey.publicKey.toString('hex');
  const asGuard = (operation: GuardOperation, signerKey = guardKey, ttl = operation.op === 'guardRead' ? 120 : 600) => {
    const g = signer.getAccount(account)!.guards?.[signerKey.publicKey.toString('hex')];
    return signer.guardSubmit(signGuardOperation({ domain: signer.domain, account, guard: signerKey.publicKey.toString('hex'), nonce: g?.nonce ?? 0, expiresAt: clock + ttl, operation }, signerKey)) as any;
  };
  op({ op: 'addAddress', address: destination });
  op({ op: 'addGuard', guard });
  clock += 2 * DAY; // destination and guard active
  return { signer, account, owner, op, asGuard, guard, guardKey, tick: (s: number) => { clock += s; }, now: () => clock };
}

test('a guard waits the address delay, at most two, never the owner key', () => {
  const { op, asGuard, account } = setup();
  const second = key();
  op({ op: 'addGuard', guard: second.publicKey.toString('hex') });
  expect(() => asGuard({ op: 'guardLock' }, second)).toThrow(/not an active guard/);
  expect(() => op({ op: 'addGuard', guard: key().publicKey.toString('hex') })).toThrow(/at most 2/);
  expect(() => op({ op: 'removeGuard', guard: second.publicKey.toString('hex') })).not.toThrow(); // waiting: dropped at once
  expect(() => op({ op: 'addGuard', guard: account })).toThrow(/owner key/);
});

test('a guard cancels requests and queued changes, and reads only what it may stop', () => {
  const { op, asGuard, signer, account } = setup();
  const r = op({ op: 'requestWithdrawal', to: destination, amount: 10_000 });
  op({ op: 'changePolicy', policy: { ...policy, withdrawalDelay: 2 * DAY } });
  const seen = asGuard({ op: 'guardRead' });
  expect(seen.requests.map((x: any) => x.id)).toEqual([r.id]);
  expect(seen.pendingPolicyAt).toBeGreaterThan(0);
  expect(JSON.stringify(seen)).not.toMatch(/accountXpub|sosUrl|generations/);
  asGuard({ op: 'guardCancelWithdrawal', requestId: r.id });
  asGuard({ op: 'guardCancelPolicyChange' });
  const a = signer.getAccount(account)!;
  expect(a.requests[0].status).toBe('cancelled');
  expect(a.pendingPolicy).toBeUndefined();
});

test('guard operations cannot be replayed and cannot pass as owner operations', () => {
  const { asGuard, signer, account, guardKey, guard, now } = setup();
  const body = { domain: signer.domain, account, guard, nonce: 0, expiresAt: now() + 600, operation: { op: 'guardLock' } as GuardOperation };
  const signed = signGuardOperation(body, guardKey);
  signer.guardSubmit(signed);
  expect(() => signer.guardSubmit(signed)).toThrow(/expected nonce 1/);
  expect(() => signer.submit({ body: { ...body, nonce: 2, operation: { op: 'unlock' } } as any, signature: signed.signature })).toThrow(/signature/);
  expect(() => asGuard({ op: 'guardLock' })).not.toThrow();
});

test('a lock voids pending requests, blocks new ones and co-signing, and lifts only after the delay', () => {
  const { op, asGuard, signer, account, owner, tick } = setup();
  // A real owner-signed withdrawal: the signer reads the request only after the owner's signature checks out (MEGA_AUDIT btc_03 M-1).
  const signerKey = Buffer.from(signer.publicKey, 'hex');
  const vault = createVault({ owner: owner.publicKey, signers: [signerKey], threshold: 1, reserveBlocks: 52_560, network });
  const spend = () => {
    const psbt = buildSpend(vault, 'cosigned', [{ txid: '22'.repeat(32), vout: 0, value: 100_000 }], [{ address: destination, value: 10_000 }, { address: vault.address, value: 89_000 }], signerKey);
    signSpend(psbt, owner);
    return psbt.toBase64();
  };
  const r = op({ op: 'requestWithdrawal', to: destination, amount: 10_000 });
  asGuard({ op: 'guardLock' });
  expect(() => op({ op: 'requestWithdrawal', to: destination, amount: 10_000 })).toThrow(/locked/);
  expect(() => op({ op: 'addAddress', address: other })).toThrow(/locked/);
  expect(() => op({ op: 'changePolicy', policy })).toThrow(/locked/);
  tick(DAY + 1);
  const a = signer.getAccount(account)!;
  expect(() => signer.signWithdrawal(account, a.head.hash, r.id, 'x')).toThrow(/cannot parse PSBT/);
  expect(() => signer.signWithdrawal(account, a.head.hash, r.id, spend())).toThrow(/locked/);
  expect(() => op({ op: 'unlock' })).toThrow(/cannot be lifted yet/);
  tick(7 * DAY);
  op({ op: 'unlock' });
  const b = signer.getAccount(account)!;
  expect(() => signer.signWithdrawal(account, b.head.hash, r.id, spend())).toThrow(/voided/);
  // A new request after unlocking works as usual.
  expect(() => op({ op: 'requestWithdrawal', to: destination, amount: 10_000 })).not.toThrow();
});

test('locking again extends the wait; the guard cannot unlock', () => {
  const { op, asGuard, signer, account, tick } = setup();
  op({ op: 'lock' });
  const first = signer.getAccount(account)!.unlockAfter!;
  tick(3 * DAY);
  asGuard({ op: 'guardLock' });
  expect(signer.getAccount(account)!.unlockAfter).toBe(first + 3 * DAY);
  expect(signer.getAccount(account)!.lockEpoch).toBe(1);
  expect(() => asGuard({ op: 'unlock' } as any)).toThrow(/unknown guard operation/);
});

test('a lock voids a destination that was still waiting; adding it again waits again', () => {
  const { op, signer, account, tick, now } = setup();
  op({ op: 'addAddress', address: other });
  op({ op: 'lock' });
  tick(7 * DAY);
  op({ op: 'unlock' });
  expect(() => op({ op: 'requestWithdrawal', to: other, amount: 10_000 })).toThrow(/not an active/);
  expect(() => op({ op: 'requestWithdrawal', to: destination, amount: 10_000 })).not.toThrow();
  const res = op({ op: 'addAddress', address: other });
  expect(res.activeAt).toBe(now() + 2 * DAY);
  tick(2 * DAY);
  expect(() => op({ op: 'requestWithdrawal', to: other, amount: 10_000 })).not.toThrow();
  expect(signer.getAccount(account)!.addressEpochs[other]).toBe(1);
});

test('removing an active guard waits the settings delay plus the lock delay (round2 L-2)', () => {
  const { op, asGuard, guard, tick } = setup();
  const { removableAt } = op({ op: 'removeGuard', guard });
  expect(() => op({ op: 'finalizeGuardRemoval', guard })).toThrow(/not elapsed/);
  tick(removableAt - 1_800_000_000);
  op({ op: 'finalizeGuardRemoval', guard });
  expect(() => asGuard({ op: 'guardLock' })).toThrow(/not an active guard/);
});

// A queued removal is visible to the guard, so it can react in time.
test('a guard sees a queued guard removal in its read', () => {
  const { op, asGuard, guard } = setup();
  expect(asGuard({ op: 'guardRead' }).pendingRemovals).toEqual([]);
  const { removableAt } = op({ op: 'removeGuard', guard });
  expect(asGuard({ op: 'guardRead' }).pendingRemovals).toEqual([{ guard, removableAt }]);
});

// Round2 L-2, as the contracts since d5ea5e3: a rogue guard re-locking cannot
// keep itself in place; the removal survives its locks and finishes under one.
test('a queued guard removal survives locks and can finish while locked', () => {
  const { op, asGuard, guard, tick } = setup();
  const { removableAt } = op({ op: 'removeGuard', guard });
  asGuard({ op: 'guardLock' });
  tick(DAY);
  asGuard({ op: 'guardLock' }); // re-locking does not drop it
  expect(asGuard({ op: 'guardRead' }).pendingRemovals).toEqual([{ guard, removableAt }]);
  tick(removableAt - 1_800_000_000);
  op({ op: 'finalizeGuardRemoval', guard });
  expect(() => asGuard({ op: 'guardLock' })).toThrow(/not an active guard/);
});

test('the lock delay never goes below the withdrawal floor', () => {
  const { op } = setup();
  expect(() => op({ op: 'changePolicy', policy: { ...policy, lockDelay: 60 } })).toThrow(/lock delay/);
});

test('while locked, a renewed coin is renewed again only a month later (NEW-M6, round2 H-2)', () => {
  const { signer, account, owner, op, tick } = setup();
  const signerKey = Buffer.from(signer.publicKey, 'hex');
  const vault = createVault({ owner: owner.publicKey, signers: [signerKey], threshold: 1, reserveBlocks: 52_560, network });
  const refresh = (txid: string, value: number) => {
    const psbt = buildSpend(vault, 'cosigned', [{ txid, vout: 0, value }], [{ address: vault.address, value: value - 1_000 }], signerKey);
    signSpend(psbt, owner);
    const out = bitcoin.Psbt.fromBase64(signer.signRefresh(account, signer.getAccount(account)!.head.hash, psbt.toBase64()), { network });
    return bitcoin.Transaction.fromBuffer(out.data.globalMap.unsignedTx.toBuffer()).getId();
  };
  const renewed = refresh('11'.repeat(32), 100_000);
  op({ op: 'lock' });
  tick(REFRESH_INTERVAL);
  expect(() => refresh(renewed, 99_000)).toThrow(/once per 30 days/);
  // Another coin (a thief's dust, say) takes no slot from it, and vice versa.
  expect(() => refresh('22'.repeat(32), 5_000)).not.toThrow();
  tick(REFRESH_INTERVAL_LOCKED - REFRESH_INTERVAL);
  expect(() => refresh(renewed, 99_000)).not.toThrow(); // still possible: the reserve door must not open behind a lock
});

test('every request carries the owner-signed recipient and amount; a made-up one is refused', () => {
  const { signer, account, owner, op, now } = setup();
  const r = op({ op: 'requestWithdrawal', to: destination, amount: 10_000 });
  // What the owner's app checks on every read.
  expect(verifyWithdrawalIntent({ domain: signer.domain, account, nonce: r.auth.nonce, to: destination, amount: 10_000 }, r.auth.signature)).toBe(true);
  expect(verifyWithdrawalIntent({ domain: signer.domain, account, nonce: r.auth.nonce, to: other, amount: 10_000 }, r.auth.signature)).toBe(false);
  // A body signed without a valid intent (e.g. by an old client) is refused.
  const a = signer.getAccount(account)!;
  const body = { domain: signer.domain, account, nonce: a.nonce, expiresAt: now() + 600, head: a.head.hash,
    operation: { op: 'requestWithdrawal', to: destination, amount: 10_000, intent: '00'.repeat(64) } as Operation };
  expect(() => signer.submit({ body, signature: owner.signSchnorr(operationDigest(body)).toString('hex') })).toThrow(/intent/);
  expect(JSON.stringify(signer.getAccount(account)!.requests)).not.toMatch(/duress/);
});
test('a guard read request is short-lived (MEGA_AUDIT btc_03 L-2)', () => {
  const { asGuard, guardKey } = setup();
  expect(() => asGuard({ op: 'guardRead' }, guardKey, 600)).toThrow(/too far ahead/);
  expect(() => asGuard({ op: 'guardRead' }, guardKey, 120)).not.toThrow();
});
