// Signer rules that need no Bitcoin node: privacy of the duress signal,
// storage bounds and the SOS URL (audit M-7, M-8, M-11).
import * as bitcoin from 'bitcoinjs-lib';
import * as ecc from '@bitcoinerlab/secp256k1';
import { ECPairFactory } from 'ecpair';
import * as bip39 from 'bip39';
import { taprootSigner } from '../src/keys';
import { ownerAccountXpub, ownerKey } from '../src/mnemonicKeys';
import { clientKey } from '../src/signer/server';
import { nextStateHash, Operation, Policy, signOperation, signRead } from '../src/signer/messages';
import { isPrivateAddress, lockDelayOf, lockedInterval, MIN_RESERVE_SECONDS_MAINNET, validateTerms, MAX_REQUESTS_PER_DAY, publicLookup, REQUEST_RETENTION, SignerService, validateSosUrl } from '../src/signer/service';

const network = bitcoin.networks.regtest;
const ECPair = ECPairFactory(ecc);
const DAY = 86400;
const policy: Policy = { withdrawalDelay: DAY, addressDelay: DAY, policyDelay: DAY, confirmationWindow: DAY, maxFee: 10_000 };

function setup(options: { registrationsPerHour?: number; onChange?: (s: any) => void } = {}) {
  let clock = 1_800_000_000;
  const kp = ECPair.makeRandom({ network });
  const signerKey = taprootSigner({ privateKey: kp.privateKey!, publicKey: Buffer.from(kp.publicKey) });
  const signer = new SignerService({ key: signerKey, network, networkName: 'regtest', now: () => clock, sendSos: () => {}, ...options });
  const register = () => {
    const mnemonic = bip39.generateMnemonic(256);
    const owner = ownerKey(mnemonic, network);
    const account = owner.publicKey.toString('hex');
    signer.submit(signOperation({
      domain: signer.domain, account, nonce: 0, expiresAt: clock + 600,
      operation: { op: 'register', accountXpub: ownerAccountXpub(mnemonic, network), policy,
        vault: { generation: 0, owner: account, signers: [signer.publicKey], threshold: 1, reserveBlocks: 52_560 },
        floors: { withdrawalDelay: 3600, addressDelay: 3600 } },
    }, owner));
    const op = (operation: Operation, duress?: boolean) => {
      const a = signer.getAccount(account)!;
      return signer.submit(signOperation({ domain: signer.domain, account, nonce: a.nonce, expiresAt: clock + 600, head: a.head.hash, duress, operation }, owner)) as any;
    };
    const read = (since?: number) => signer.readAccount(signRead({ domain: signer.domain, account, expiresAt: clock + 60, operation: { op: 'read', since } }, owner));
    return { account, op, read, mnemonic };
  };
  return { signer, register, tick: (s: number) => { clock += s; } };
}

const destination = bitcoin.payments.p2tr({ internalPubkey: Buffer.alloc(32, 2), network }).address!;

test('a duress request and the SOS time are invisible to whoever reads the account (M-7)', () => {
  const { register, tick } = setup();
  const { op, read } = register();
  op({ op: 'setSos', url: 'https://sos.example/hook' });
  op({ op: 'addAddress', address: destination });
  tick(DAY);
  op({ op: 'requestWithdrawal', to: destination, amount: 10_000 }, true);
  expect(JSON.stringify(read())).not.toMatch(/duress|lastSos/i);
});

test('a read with since returns the events that link the heads (M-8)', () => {
  const { register } = setup();
  const { op, read } = register();
  const before = read();
  op({ op: 'addAddress', address: destination });
  op({ op: 'removeAddress', address: destination });
  const after = read(before.head.seq);
  expect(after.events!.map(e => e.seq)).toEqual([before.head.seq + 1, before.head.seq + 2]);
  const hash = after.events!.reduce((h, e) => nextStateHash(h, e.event), before.head.hash);
  expect(hash).toBe(after.head.hash);
  expect(read()).not.toHaveProperty('log');
});

test('withdrawal requests are rate-limited and old ones pruned with stable ids (M-11)', () => {
  const { register, tick } = setup();
  const { op, read } = register();
  op({ op: 'addAddress', address: destination });
  tick(DAY);
  for (let i = 0; i < MAX_REQUESTS_PER_DAY; i++) {
    const r = op({ op: 'requestWithdrawal', to: destination, amount: 10_000 });
    op({ op: 'cancelWithdrawal', requestId: r.id });
  }
  expect(() => op({ op: 'requestWithdrawal', to: destination, amount: 10_000 })).toThrow(/today/);
  tick(3 * DAY + REQUEST_RETENTION);
  const next = op({ op: 'requestWithdrawal', to: destination, amount: 10_000 });
  expect(next.id).toBe(MAX_REQUESTS_PER_DAY);
  const account = read();
  expect(account.requests).toHaveLength(1);
  expect(account.requestBase).toBe(MAX_REQUESTS_PER_DAY);
  op({ op: 'cancelWithdrawal', requestId: next.id });
  expect(read().requests[0].status).toBe('cancelled');
});

test('registrations are limited per hour (M-11)', () => {
  const { register, tick } = setup({ registrationsPerHour: 2 });
  register();
  register();
  expect(() => register()).toThrow(/too many new accounts/);
  tick(3601);
  expect(() => register()).not.toThrow();
});

test('the SOS URL must be a public https host (M-11)', () => {
  for (const bad of ['http://sos.example/x', 'https://127.0.0.1/x', 'https://10.1.2.3/x', 'https://169.254.169.254/latest',
    'https://[::1]/x', 'https://localhost/x', 'https://router.local/x', 'https://metadata.internal/x', 'https://u:p@sos.example/x'])
    expect(() => validateSosUrl(bad)).toThrow();
  expect(() => validateSosUrl('https://sos.example/hook')).not.toThrow();
  expect(() => validateSosUrl('http://127.0.0.1:8080/x')).toThrow();
  expect(() => validateSosUrl('http://127.0.0.1:8080/x', true)).not.toThrow();
  expect(['192.168.1.1', '172.20.0.1', '100.64.0.1', '::ffff:10.0.0.1', 'fd00::1', 'fe80::1'].every(isPrivateAddress)).toBe(true);
  expect(['8.8.8.8', '1.1.1.1', '2606:4700::1111', '172.32.0.1'].some(isPrivateAddress)).toBe(false);
});

test('SOS lookup answers in the form Node asks for and refuses private hosts (M-11)', async () => {
  const ask = (all: boolean) => new Promise<any[]>(resolve => publicLookup('localhost', { all }, (...args: any[]) => resolve(args)));
  for (const all of [true, false]) {
    const [err] = await ask(all);
    expect(err?.code).toBe('EPRIVATE');
  }
  // What https.request does on Node 20+: all: true, expecting an array back.
  const https = require('https');
  const error: any = await new Promise(resolve => {
    const req = https.request('https://localhost:1/', { lookup: publicLookup, timeout: 2000 }, () => resolve(null));
    req.on('error', resolve);
    req.end();
  });
  expect(error.code).toBe('EPRIVATE');
});

test('the per-client registration limit treats an IPv6 /64 as one client (M-11 review)', () => {
  expect(clientKey('2001:db8:1:2:aaaa::1')).toBe(clientKey('2001:db8:1:2:ffff:1:2:3'));
  expect(clientKey('2001:db8:1:2::1')).not.toBe(clientKey('2001:db8:1:3::1'));
  expect(clientKey('::ffff:203.0.113.7')).toBe('203.0.113.7');
  expect(clientKey('203.0.113.7')).toBe('203.0.113.7');
  expect(clientKey('2001:db8::1')).toBe('2001:0db8:0000:0000::/64');
});

test('a change the signer cannot save is not applied at all', () => {
  let failWrites = false;
  const { signer, register } = setup({ onChange: () => { if (failWrites) throw new Error('disk full'); } });
  const { account, op } = register();
  const before = JSON.stringify(signer.getAccount(account));
  failWrites = true;
  expect(() => op({ op: 'addAddress', address: destination })).toThrow(/could not save/);
  expect(JSON.stringify(signer.getAccount(account))).toBe(before);
  failWrites = false;
  expect(op({ op: 'addAddress', address: destination })).toHaveProperty('activeAt');
});

test('under a Panic Lock new vault generations come at most once in 30 days (R-19)', () => {
  const { register, tick, signer } = setup();
  const { op, mnemonic } = register();
  const gen = (n: number) => ({ op: 'addGeneration' as const, vault: {
    generation: n, owner: ownerKey(mnemonic, network, n).publicKey.toString('hex'), signers: [signer.publicKey], threshold: 1, reserveBlocks: 52_560,
  } });
  tick(DAY);
  op(gen(1));
  op({ op: 'lock' });
  tick(DAY + 1);
  expect(() => op(gen(2))).toThrow(/30 days/);
  tick(30 * DAY);
  expect(() => op(gen(2))).not.toThrow();
});

test('a short reserve door shortens the locked spacing, so renewals still come in time (A11-9)', () => {
  // 7-day reserve on Bitcoin: renewals at most every quarter of it (~1.75 d), not every 30 days.
  expect(lockedInterval({ generations: [{ reserveBlocks: 7 * 144 } as any] }, 600)).toBe(Math.floor(7 * DAY / 4));
  // A year-long reserve keeps the 30-day spacing.
  expect(lockedInterval({ generations: [{ reserveBlocks: 52_560 } as any] }, 600)).toBe(30 * DAY);
  // A 100-minute reserve (A13-4): renewals every 25 minutes, not once a day.
  expect(lockedInterval({ generations: [{ reserveBlocks: 10 } as any] }, 600)).toBe(1500);
});

test('the lock delay is never shorter than the current withdrawal delay (A12-3)', () => {
  expect(lockDelayOf({ ...policy, withdrawalDelay: 30 * DAY, lockDelay: DAY })).toBe(30 * DAY);
  expect(lockDelayOf({ ...policy, withdrawalDelay: DAY, lockDelay: 10 * DAY })).toBe(10 * DAY);
});

test('on the main networks the reserve door is at least two locked renewal intervals (A13-4)', () => {
  const minBtc = Math.ceil(MIN_RESERVE_SECONDS_MAINNET / 600);
  const terms = (reserveBlocks: number) => ({ signers: ['aa'.repeat(32), 'bb'.repeat(32), 'cc'.repeat(32)], threshold: 2, reserveBlocks, heir: undefined, heirBlocks: undefined });
  expect(() => validateTerms(terms(1000), undefined, minBtc)).toThrow(/reserve period/);
  expect(() => validateTerms(terms(52_560), undefined, minBtc)).not.toThrow(); // the app's Bitcoin door, ~1 year
  expect(Math.ceil(MIN_RESERVE_SECONDS_MAINNET / 150)).toBeLessThanOrEqual(57_600); // the app's Litecoin door, ~100 days
});
