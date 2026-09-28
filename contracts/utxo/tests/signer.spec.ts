import * as bitcoin from 'bitcoinjs-lib';
import * as ecc from '@bitcoinerlab/secp256k1';
import { ECPairFactory } from 'ecpair';
import * as bip39 from 'bip39';
import { createVault, Vault } from '../src/vault';
import { buildCosignedSpend, buildSpend, finalizeCosignedSpend, finalizeSpend, signSpend, Signer, VaultUtxo } from '../src/spend';
import { taprootSigner } from '../src/keys';
import { heirKey, ownerAccountXpub, ownerKey } from '../src/mnemonicKeys';
import { Operation, Policy, signOperation, VaultConfig } from '../src/signer/messages';
import { MAX_PENDING_REQUESTS, postSos, REFRESH_INTERVAL, SignerService, SOS_INTERVAL, SosPayload } from '../src/signer/service';
import { createServer } from 'http';
import { AddressInfo } from 'net';
import { Regtest } from './regtest';

const network = bitcoin.networks.regtest;
const ECPair = ECPairFactory(ecc);
const DAY = 86400;
const FEE = 1_000;
const RESERVE = 10;

const policy: Policy = {
  withdrawalDelay: 3 * DAY, addressDelay: 30 * DAY, policyDelay: 30 * DAY,
  confirmationWindow: DAY, maxFee: 10_000,
};

function randomKey(): Signer {
  const kp = ECPair.makeRandom({ network });
  return taprootSigner({ privateKey: kp.privateKey!, publicKey: Buffer.from(kp.publicKey) });
}

const hex = (k: Signer) => k.publicKey.toString('hex');

describe('Bitcoin signer', () => {
  const node = new Regtest();
  let clock = 1_800_000_000;
  const mnemonic = bip39.generateMnemonic(256);
  const owner = ownerKey(mnemonic, network);
  const heir = heirKey(bip39.generateMnemonic(256), network);
  const signerKey = randomKey();
  const duressCalls: string[] = [];
  const sosCalls: { url: string; payload: SosPayload }[] = [];
  let signer: SignerService;
  let config: VaultConfig;
  let vault: Vault;
  let nonce = 0;
  let destination: string;
  let attacker: string;

  const head = () => signer.getAccount(hex(owner))?.head.hash as string;
  const op = (operation: Operation, extra: { duress?: boolean; nonce?: number; expiresAt?: number; key?: Signer } = {}) =>
    signer.submit(signOperation({
      domain: signer.domain, account: hex(owner), nonce: extra.nonce ?? nonce++, expiresAt: extra.expiresAt ?? clock + 600,
      duress: extra.duress, head: operation.op === 'register' ? undefined : head(), operation,
    }, extra.key ?? owner)) as any;

  const withdrawalPsbt = (utxo: VaultUtxo, outputs: { address: string; value: number }[], from = vault, key = owner) => {
    const psbt = buildSpend(from, 'cosigned', [utxo], outputs, signerKey.publicKey);
    signSpend(psbt, key);
    return psbt.toBase64();
  };

  const broadcastSigned = async (base64: string, from = vault) => {
    const tx = finalizeSpend(bitcoin.Psbt.fromBase64(base64, { network }), from, 'cosigned', signerKey.publicKey);
    const result = await node.test(tx.toHex());
    return result;
  };

  beforeAll(async () => {
    await node.start();
    destination = await node.rpc('getnewaddress', ['', 'bech32m'], 'miner');
    attacker = await node.rpc('getnewaddress', ['', 'bech32m'], 'miner');
    signer = new SignerService({
      key: signerKey, network, networkName: 'regtest', now: () => clock, onDuress: a => duressCalls.push(a),
      sendSos: (url, payload) => sosCalls.push({ url, payload }),
    });
    config = { generation: 0, owner: hex(owner), signers: [signer.publicKey], threshold: 1, reserveBlocks: RESERVE, heir: hex(heir), heirBlocks: 2 * RESERVE };
    vault = createVault({
      owner: owner.publicKey, signers: [signerKey.publicKey], threshold: 1, reserveBlocks: RESERVE,
      heir: heir.publicKey, heirBlocks: 2 * RESERVE, network,
    });
    const reg = op({ op: 'register', accountXpub: ownerAccountXpub(mnemonic, network), vault: config, policy, floors: { withdrawalDelay: DAY, addressDelay: DAY } });
    expect(reg.address).toBe(vault.address);
  }, 60_000);

  afterAll(() => node.stop(), 30_000);

  it('full withdrawal: allowlist -> address delay -> request -> withdrawal delay -> co-sign', async () => {
    const { activeAt } = op({ op: 'addAddress', address: destination });
    expect(activeAt).toBe(clock + 30 * DAY);
    expect(() => op({ op: 'requestWithdrawal', to: destination, amount: 50_000 }, { nonce })).toThrow(/not an active/);

    clock += 30 * DAY;
    const utxo = await node.fund(vault.address, 100_000);
    const request = op({ op: 'requestWithdrawal', to: destination, amount: 50_000 });
    const psbt = withdrawalPsbt(utxo, [{ address: destination, value: 50_000 }, { address: vault.address, value: 50_000 - FEE }]);
    expect(() => signer.signWithdrawal(hex(owner), head(), request.id, psbt)).toThrow(/delay has not elapsed/);

    clock += 3 * DAY;
    const signed = signer.signWithdrawal(hex(owner), head(), request.id, psbt);
    expect(await broadcastSigned(signed)).toMatchObject({ allowed: true });

    // A fee bump may be re-signed, but only spending exactly the same coins,
    // so the versions conflict and at most one can confirm.
    const bumped = withdrawalPsbt(utxo, [{ address: destination, value: 50_000 }, { address: vault.address, value: 50_000 - 3 * FEE }]);
    expect(await broadcastSigned(signer.signWithdrawal(hex(owner), head(), request.id, bumped))).toMatchObject({ allowed: true });
    const other = await node.fund(vault.address, 100_000);
    const second = withdrawalPsbt(other, [{ address: destination, value: 50_000 }, { address: vault.address, value: 50_000 - FEE }]);
    expect(() => signer.signWithdrawal(hex(owner), head(), request.id, second)).toThrow(/same inputs/);
  });

  it('refuses a transaction that differs from the request', async () => {
    const utxo = await node.fund(vault.address, 100_000);
    const request = op({ op: 'requestWithdrawal', to: destination, amount: 50_000 });
    clock += 3 * DAY;
    const cases = [
      [{ address: attacker, value: 50_000 }, { address: vault.address, value: 50_000 - FEE }],       // other destination
      [{ address: destination, value: 60_000 }, { address: vault.address, value: 40_000 - FEE }],    // other amount
      [{ address: destination, value: 50_000 }, { address: attacker, value: 50_000 - FEE }],         // change to attacker
      [{ address: destination, value: 50_000 }, { address: vault.address, value: 20_000 }],          // huge fee
    ];
    for (const outputs of cases) {
      expect(() => signer.signWithdrawal(hex(owner), head(), request.id, withdrawalPsbt(utxo, outputs))).toThrow();
    }
    // The request is still usable with the correct transaction.
    const ok = signer.signWithdrawal(hex(owner), head(), request.id,
      withdrawalPsbt(utxo, [{ address: destination, value: 50_000 }, { address: vault.address, value: 50_000 - FEE }]));
    expect(await broadcastSigned(ok)).toMatchObject({ allowed: true });
  });

  it('requires the owner signature as the confirmation step', async () => {
    const utxo = await node.fund(vault.address, 100_000);
    const request = op({ op: 'requestWithdrawal', to: destination, amount: 50_000 });
    clock += 3 * DAY;
    const unsigned = buildSpend(vault, 'cosigned', [utxo],
      [{ address: destination, value: 50_000 }, { address: vault.address, value: 50_000 - FEE }], signerKey.publicKey);
    expect(() => signer.signWithdrawal(hex(owner), head(), request.id, unsigned.toBase64())).toThrow(/owner signature/);
    // A signature by some other key, labelled as the owner's, is rejected.
    const forged = buildSpend(vault, 'cosigned', [utxo],
      [{ address: destination, value: 50_000 }, { address: vault.address, value: 50_000 - FEE }], signerKey.publicKey);
    signSpend(forged, signerKey);
    const sig = forged.data.inputs[0].tapScriptSig![0];
    forged.updateInput(0, { tapScriptSig: [{ ...sig, pubkey: owner.publicKey }] });
    expect(() => signer.signWithdrawal(hex(owner), head(), request.id, forged.toBase64())).toThrow(/owner signature/);
  });

  it('cancel and address removal block a pending request', async () => {
    const utxo = await node.fund(vault.address, 100_000);
    const outputs = [{ address: destination, value: 50_000 }, { address: vault.address, value: 50_000 - FEE }];
    const cancelled = op({ op: 'requestWithdrawal', to: destination, amount: 50_000 });
    op({ op: 'cancelWithdrawal', requestId: cancelled.id });
    const revoked = op({ op: 'requestWithdrawal', to: destination, amount: 50_000 });
    op({ op: 'removeAddress', address: destination });
    op({ op: 'addAddress', address: destination }); // re-adding restarts the address delay
    clock += 3 * DAY;
    expect(() => signer.signWithdrawal(hex(owner), head(), cancelled.id, withdrawalPsbt(utxo, outputs))).toThrow(/no pending/);
    expect(() => signer.signWithdrawal(hex(owner), head(), revoked.id, withdrawalPsbt(utxo, outputs))).toThrow(/no longer allowlisted/);
    clock += 30 * DAY; // destination active again, but the old request stays dead
    expect(() => signer.signWithdrawal(hex(owner), head(), revoked.id, withdrawalPsbt(utxo, outputs))).toThrow(/no longer allowlisted/);
  });

  it('a request expires after the confirmation window', async () => {
    const utxo = await node.fund(vault.address, 100_000);
    const request = op({ op: 'requestWithdrawal', to: destination, amount: 50_000 });
    clock += 4 * DAY + 1;
    expect(() => signer.signWithdrawal(hex(owner), head(), request.id,
      withdrawalPsbt(utxo, [{ address: destination, value: 50_000 }, { address: vault.address, value: 50_000 - FEE }]))).toThrow(/window/);
  });

  it('refresh into a new generation is co-signed immediately', async () => {
    const next = ownerKey(mnemonic, network, 1);
    const nextConfig = { ...config, generation: 1, owner: hex(next) };
    const { address } = op({ op: 'addGeneration', vault: nextConfig });
    const utxo = await node.fund(vault.address, 100_000);
    const signed = signer.signRefresh(hex(owner), head(), withdrawalPsbt(utxo, [{ address, value: 100_000 - FEE }]));
    expect(await broadcastSigned(signed)).toMatchObject({ allowed: true });
    expect(() => signer.signRefresh(hex(owner), head(), withdrawalPsbt(utxo, [{ address: attacker, value: 100_000 - FEE }]))).toThrow(/only pay into this vault/);
  });

  it('refuses to refresh into a weaker vault (shorter reserve, new heir, other signers)', () => {
    const k = (i: number) => ({ generation: i, owner: hex(ownerKey(mnemonic, network, i)) });
    expect(() => op({ op: 'addGeneration', vault: { ...config, ...k(2), reserveBlocks: 1 } }, { nonce })).toThrow(/weaker/);
    expect(() => op({ op: 'addGeneration', vault: { ...config, ...k(3), heir: hex(randomKey()) } }, { nonce })).toThrow(/weaker/);
    expect(() => op({ op: 'addGeneration', vault: { ...config, ...k(4), heirBlocks: RESERVE + 1 } }, { nonce })).toThrow(/weaker/);
    expect(() => op({ op: 'addGeneration', vault: { ...config, ...k(5), signers: [signer.publicKey, hex(randomKey())], threshold: 1 } }, { nonce })).toThrow(/weaker/);
    // Several signers with no threshold is refused outright (A10-2), never read as "any one".
    expect(() => op({ op: 'addGeneration', vault: { ...config, ...k(5), signers: [signer.publicKey, hex(randomKey())], threshold: undefined as any } }, { nonce })).toThrow(/threshold must be between/);
    // Audit H-2: a longer reserve (~455 days on Bitcoin) is not "stronger" here —
    // moving coins there instantly would lock the owner out of the reserve door.
    expect(() => op({ op: 'addGeneration', vault: { ...config, ...k(6), reserveBlocks: 65535, heirBlocks: undefined, heir: undefined } }, { nonce })).toThrow(/weaker/);
    // Removing the heir is not allowed either without a (delayed) policy change.
    expect(() => op({ op: 'addGeneration', vault: { ...config, ...k(6), heir: undefined, heirBlocks: undefined } }, { nonce })).toThrow(/weaker/);
  });

  it('refuses a generation keyed to anything but the owner account xpub', () => {
    // A seed thief tries to refresh coins into a vault only they can sign for.
    const thiefKey = hex(randomKey());
    expect(() => op({ op: 'addGeneration', vault: { ...config, generation: 7, owner: thiefKey } }, { nonce })).toThrow(/not derived/);
    // Right key, wrong generation index.
    expect(() => op({ op: 'addGeneration', vault: { ...config, generation: 8, owner: hex(ownerKey(mnemonic, network, 9)) } }, { nonce })).toThrow(/not derived/);
    // Re-registering an existing generation.
    expect(() => op({ op: 'addGeneration', vault: { ...config, generation: 1, owner: hex(ownerKey(mnemonic, network, 1)) } }, { nonce })).toThrow(/already registered/);
  });

  it('limits refreshes so a stolen seed cannot burn the vault in fees', async () => {
    const next = ownerKey(mnemonic, network, 1);
    const target = createVault({ owner: next.publicKey, signers: [signerKey.publicKey], threshold: 1, reserveBlocks: RESERVE, heir: heir.publicKey, heirBlocks: 2 * RESERVE, network });
    const utxo = await node.fund(vault.address, 100_000);
    const psbt = withdrawalPsbt(utxo, [{ address: target.address, value: 100_000 - FEE }]);
    expect(() => signer.signRefresh(hex(owner), head(), psbt)).toThrow(/one per day/);
    clock += REFRESH_INTERVAL;
    expect(() => signer.signRefresh(hex(owner), head(), psbt)).not.toThrow();
  });

  it('a withdrawal can combine coins from several generations', async () => {
    const gen1Key = ownerKey(mnemonic, network, 1);
    const gen1 = createVault({ owner: gen1Key.publicKey, signers: [signerKey.publicKey], threshold: 1, reserveBlocks: RESERVE, heir: heir.publicKey, heirBlocks: 2 * RESERVE, network });
    const a = await node.fund(vault.address, 30_000);
    const b = await node.fund(gen1.address, 30_000);
    const request = op({ op: 'requestWithdrawal', to: destination, amount: 50_000 });
    clock += 3 * DAY;
    const psbt = buildCosignedSpend([{ vault, utxos: [a] }, { vault: gen1, utxos: [b] }],
      [{ address: destination, value: 50_000 }, { address: gen1.address, value: 10_000 - FEE }], signerKey.publicKey);
    signSpend(psbt, owner);     // signs only the generation-0 input
    signSpend(psbt, gen1Key);   // signs only the generation-1 input
    const cosigned = bitcoin.Psbt.fromBase64(signer.signWithdrawal(hex(owner), head(), request.id, psbt.toBase64()), { network });
    const tx = finalizeCosignedSpend(cosigned, [vault, gen1], signerKey.publicKey);
    expect(await node.test(tx.toHex())).toMatchObject({ allowed: true });
  });

  it('refuses sighash types that do not commit to every output', async () => {
    const utxo = await node.fund(vault.address, 100_000);
    const request = op({ op: 'requestWithdrawal', to: destination, amount: 50_000 });
    clock += 3 * DAY;
    const psbt = buildSpend(vault, 'cosigned', [utxo],
      [{ address: destination, value: 50_000 }, { address: vault.address, value: 50_000 - FEE }], signerKey.publicKey);
    psbt.updateInput(0, { sighashType: bitcoin.Transaction.SIGHASH_NONE | bitcoin.Transaction.SIGHASH_ANYONECANPAY });
    const ownerSigner = { ...owner, sign: () => { throw new Error('unused'); } };
    psbt.signTaprootInput(0, ownerSigner, undefined, [psbt.data.inputs[0].sighashType!]);
    expect(() => signer.signWithdrawal(hex(owner), head(), request.id, psbt.toBase64())).toThrow(/sighash/);
  });

  it('every policy change waits the policy delay, including stronger ones', () => {
    const weaker = { ...policy, withdrawalDelay: DAY };
    expect(op({ op: 'changePolicy', policy: weaker })).toMatchObject({ applied: false });
    expect(() => op({ op: 'applyPolicyChange' }, { nonce })).toThrow(/not elapsed/);
    // A "stronger" change (longer delays, zero fee cap, 1-second window) must not
    // apply at once: instantly it would let a thief lock the owner out.
    const lockout = { ...policy, withdrawalDelay: 90 * DAY, addressDelay: 90 * DAY, confirmationWindow: 1, maxFee: 0 };
    expect(op({ op: 'changePolicy', policy: lockout })).toMatchObject({ applied: false });
    expect(signer.getAccount(hex(owner))!.policy).toEqual(policy);
    // Changing the heir key waits too.
    expect(op({ op: 'changePolicy', policy: { ...policy, heir: hex(randomKey()) } })).toMatchObject({ applied: false });
    op({ op: 'cancelPolicyChange' });
    expect(signer.getAccount(hex(owner))!.pendingPolicy).toBeUndefined();
  });

  it('never lets the reserve period go below generation 0 (permanent floor)', () => {
    expect(() => op({ op: 'changePolicy', policy: { ...policy, reserveBlocks: 1 } }, { nonce })).toThrow(/permanent minimum/);
    expect(() => op({ op: 'changePolicy', policy: { ...policy, reserveBlocks: RESERVE - 1 } }, { nonce })).toThrow(/permanent minimum/);
    // Lengthening is allowed, but only as a delayed change.
    expect(op({ op: 'changePolicy', policy: { ...policy, reserveBlocks: RESERVE + 5 } })).toMatchObject({ applied: false });
    op({ op: 'cancelPolicyChange' });
  });

  it('never lets delays go below the permanent minimums', () => {
    expect(() => op({ op: 'changePolicy', policy: { ...policy, withdrawalDelay: DAY - 1 } }, { nonce })).toThrow(/permanent minimums/);
    expect(() => op({ op: 'changePolicy', policy: { ...policy, addressDelay: 60 } }, { nonce })).toThrow(/permanent minimums/);
    // At the floor is allowed (as a delayed, weakening change).
    expect(op({ op: 'changePolicy', policy: { ...policy, withdrawalDelay: DAY } })).toMatchObject({ applied: false });
    op({ op: 'cancelPolicyChange' });
  });

  it('caps the number of pending requests', () => {
    const acct = signer.getAccount(hex(owner))!;
    const open = acct.requests.filter(r => r.status === 'pending' && r.expiresAt >= clock).length;
    for (let i = open; i < MAX_PENDING_REQUESTS; i++) op({ op: 'requestWithdrawal', to: destination, amount: 1_000 });
    expect(() => op({ op: 'requestWithdrawal', to: destination, amount: 1_000 }, { nonce })).toThrow(/too many pending/);
    clock += 5 * DAY; // they expire and stop counting
    expect(op({ op: 'requestWithdrawal', to: destination, amount: 1_000 })).toMatchObject({ status: 'pending' });
  });

  it('rejects operations signed for another signer or network', () => {
    const base = { account: hex(owner), nonce, expiresAt: clock + 600, head: head(), operation: { op: 'cancelPolicyChange' } as Operation };
    const otherSigner = signOperation({ ...base, domain: { network: 'regtest', signer: hex(randomKey()) } }, owner);
    const otherNet = signOperation({ ...base, domain: { network: 'signet', signer: signer.publicKey } }, owner);
    expect(() => signer.submit(otherSigner)).toThrow(/different signer or network/);
    expect(() => signer.submit(otherNet)).toThrow(/different signer or network/);
  });

  it('rejects replayed, expired, foreign-signed and out-of-order operations', () => {
    const body = { domain: signer.domain, account: hex(owner), nonce, expiresAt: clock + 600, head: head(), operation: { op: 'cancelPolicyChange' } as Operation };
    const signed = signOperation(body, owner);
    signer.submit(signed);
    nonce++;
    expect(() => signer.submit(signed)).toThrow(/nonce|head/);
    expect(() => op({ op: 'cancelPolicyChange' }, { nonce, expiresAt: clock - 1 })).toThrow(/expired/);
    expect(() => op({ op: 'cancelPolicyChange' }, { nonce, expiresAt: clock + 7200 })).toThrow(/expired/);
    expect(() => op({ op: 'cancelPolicyChange' }, { nonce, key: randomKey() })).toThrow(/signature/);
    expect(() => op({ op: 'cancelPolicyChange' }, { nonce: nonce + 5 })).toThrow(/nonce/);
  });

  it('detects a signer restored from an old backup (rollback)', () => {
    const backup = JSON.parse(JSON.stringify({ accounts: { [hex(owner)]: signer.getAccount(hex(owner)) } }));
    const clientHead = head(); // what the owner's app remembers
    op({ op: 'removeAddress', address: attacker });
    const latest = head();
    expect(latest).not.toBe(clientHead);
    // The server is restored from the backup: the removal is "forgotten".
    const restored = new SignerService({ key: signerKey, network, networkName: 'regtest', now: () => clock, state: backup });
    const body = { domain: restored.domain, account: hex(owner), nonce: restored.getAccount(hex(owner))!.nonce, expiresAt: clock + 600, head: latest, operation: { op: 'cancelPolicyChange' } as Operation };
    expect(() => restored.submit(signOperation(body, owner))).toThrow(/head mismatch/);
  });

  it('reports duress silently without changing the response', () => {
    const plain = op({ op: 'addAddress', address: attacker });
    const duress = op({ op: 'addAddress', address: attacker }, { duress: true });
    const { head: h1, ...p1 } = plain;
    const { head: h2, ...p2 } = duress;
    expect(p2).toEqual(p1);
    expect(duressCalls).toEqual([hex(owner)]);
    expect(sosCalls).toEqual([]); // no SOS configured -> nothing is sent
  });

  // Audit A15-4 / A16-1: every SOS change, the first one too, waits like a
  // policy change; the current address is told; a lock drops the change; and
  // nothing about SOS is returned to a reader.
  it('an SOS change waits, the old address is told, a lock drops it, and reads never show it', () => {
    const A = () => signer.getAccount(hex(owner))!;
    op({ op: 'setSos', url: 'https://sos.example/hook' });
    op({ op: 'addAddress', address: attacker }, { duress: true });
    expect(sosCalls).toEqual([]); // not in effect yet
    const wait = Math.max(A().policy.policyDelay, A().floors.withdrawalDelay + A().floors.addressDelay, A().policy.withdrawalDelay);
    expect(A().pendingSos!.effectiveAt).toBe(clock + wait);
    clock = A().pendingSos!.effectiveAt;
    op({ op: 'setSos', url: 'https://thief.example/hook' }); // applies the first, queues the second
    expect(A().sosUrl).toBe('https://sos.example/hook');
    expect(sosCalls.map(c => [c.url, c.payload.event])).toEqual([['https://sos.example/hook', 'avelock-sos-change']]);
    // Repeated requests within SOS_INTERVAL send no more notices (A16-4).
    op({ op: 'setSos', url: 'https://thief2.example/hook' });
    op({ op: 'setSos', url: 'https://thief3.example/hook' });
    expect(sosCalls).toHaveLength(1);
    op({ op: 'lock' });
    expect(A().pendingSos).toBeUndefined();
    expect(() => op({ op: 'setSos', url: null }, { nonce })).toThrow(/locked/);
    clock = A().unlockAfter!;
    op({ op: 'unlock' });
    op({ op: 'setSos', url: null });
    clock = A().pendingSos!.effectiveAt;
    op({ op: 'addAddress', address: attacker }, { duress: true });
    expect(A().sosUrl).toBeUndefined();
    expect(sosCalls.filter(c => c.payload.event === 'avelock-duress')).toEqual([]);
    sosCalls.length = 0;
    // Leave the shared account as later tests expect it: attacker not allowed.
    if (JSON.stringify(A()).includes(attacker)) op({ op: 'removeAddress', address: attacker });
  });

  it('sends a rate-limited SOS on duress when configured', () => {
    expect(() => op({ op: 'setSos', url: 'http://example.com/hook' }, { nonce })).toThrow(/https/);
    op({ op: 'setSos', url: 'https://sos.example/hook' });
    clock = signer.getAccount(hex(owner))!.pendingSos!.effectiveAt;
    op({ op: 'addAddress', address: attacker }, { duress: true });
    op({ op: 'addAddress', address: attacker }, { duress: true }); // within the interval
    expect(sosCalls).toEqual([{ url: 'https://sos.example/hook', payload: { event: 'avelock-duress', account: hex(owner), at: clock } }]);
    clock += SOS_INTERVAL;
    op({ op: 'addAddress', address: attacker }, { duress: true });
    expect(sosCalls).toHaveLength(2);
    op({ op: 'addAddress', address: attacker }); // normal session: no SOS
    expect(sosCalls).toHaveLength(2);
  });

  it('a failing SOS sender never affects the operation', () => {
    const failing = new SignerService({
      key: signerKey, network, networkName: 'regtest', now: () => clock,
      state: JSON.parse(JSON.stringify({ accounts: { [hex(owner)]: signer.getAccount(hex(owner)) } })),
      sendSos: () => { throw new Error('network down'); },
    });
    const a = failing.getAccount(hex(owner))!;
    a.lastSosAt = undefined;
    const body = { domain: failing.domain, account: hex(owner), nonce: a.nonce, expiresAt: clock + 600, head: a.head.hash, duress: true,
      operation: { op: 'addAddress', address: attacker } as Operation };
    expect(failing.submit(signOperation(body, owner))).toHaveProperty('activeAt');
  });

  it('postSos delivers the signal over HTTP in the background', async () => {
    const received: unknown[] = [];
    const hook = createServer((req, res) => {
      let data = '';
      req.on('data', c => { data += c; });
      req.on('end', () => { received.push(JSON.parse(data)); res.end(); });
    });
    await new Promise<void>(r => hook.listen(0, '127.0.0.1', r));
    const url = `http://127.0.0.1:${(hook.address() as AddressInfo).port}/sos`;
    postSos(url, { event: 'avelock-duress', account: 'ab', at: 1 });
    for (let i = 0; i < 50 && received.length === 0; i++) await new Promise(r => setTimeout(r, 20));
    hook.close();
    expect(received).toEqual([{ event: 'avelock-duress', account: 'ab', at: 1 }]);
  });

  it('a stolen seed alone still waits every delay', async () => {
    // The thief has the owner seed and can sign operations, but gets the
    // same delays as the owner, who sees and can cancel the request.
    op({ op: 'addAddress', address: attacker });
    expect(() => op({ op: 'requestWithdrawal', to: attacker, amount: 50_000 }, { nonce })).toThrow(/not an active/);
    const utxo = await node.fund(vault.address, 100_000);
    const psbt = buildSpend(vault, 'cosigned', [utxo], [{ address: attacker, value: 100_000 - FEE }], signerKey.publicKey);
    signSpend(psbt, owner);
    expect(() => signer.signRefresh(hex(owner), head(), psbt.toBase64())).toThrow(/only pay into this vault/);
  });

  // Review of H-2: the resulting terms must describe a buildable vault, or no
  // renewal can ever match them (a lock-out a thief could schedule).
  it('rejects policies no vault can meet, and removing the heir keeps renewals working', () => {
    expect(() => op({ op: 'changePolicy', policy: { ...policy, reserveBlocks: 2 * RESERVE } }, { nonce })).toThrow(/longer than the reserve/);
    expect(() => op({ op: 'changePolicy', policy: { ...policy, reserveBlocks: 3 * RESERVE } }, { nonce })).toThrow(/longer than the reserve/);
    expect(op({ op: 'changePolicy', policy: { ...policy, heir: null } })).toMatchObject({ applied: false });
    clock += policy.policyDelay + 1;
    op({ op: 'applyPolicyChange' });
    const k = { generation: 30, owner: hex(ownerKey(mnemonic, network, 30)) };
    const { heir: _h, heirBlocks: _b, ...heirless } = config;
    expect(op({ op: 'addGeneration', vault: { ...heirless, ...k } })).toHaveProperty('address');
  });

  it('rejects a policy whose heir no renewal can accept (signer key, off-curve, own future key)', () => {
    expect(() => op({ op: 'changePolicy', policy: { ...policy, heir: signer.publicKey } }, { nonce })).toThrow(/no vault can be built/);
    expect(() => op({ op: 'changePolicy', policy: { ...policy, heir: 'ff'.repeat(32) } }, { nonce })).toThrow(/no vault can be built/);
    const future = hex(ownerKey(mnemonic, network, 40));
    expect(() => op({ op: 'changePolicy', policy: { ...policy, heir: future, heirBlocks: 2 * RESERVE } }, { nonce })).toThrow(/own vault keys/);
  });

  it('adds at most one generation a day, so the generation limit cannot be filled at once', () => {
    clock += 2 * DAY;
    const gen = (i: number) => ({ ...config, generation: i, owner: hex(ownerKey(mnemonic, network, i)) });
    const { heir: _h, heirBlocks: _b, ...rest } = gen(50);
    const current = signer.getAccount(hex(owner))!.policy.heir === null ? rest : gen(50);
    expect(op({ op: 'addGeneration', vault: current })).toHaveProperty('address');
    const next = { ...current, generation: 51, owner: hex(ownerKey(mnemonic, network, 51)) };
    expect(() => op({ op: 'addGeneration', vault: next }, { nonce })).toThrow(/one new vault generation per day/);
    clock += DAY;
    expect(op({ op: 'addGeneration', vault: next })).toHaveProperty('address');
  });

  // Audit A3-1: a "__proto__" key must never reach Object.prototype.
  it('rejects "__proto__" and other malformed guard keys without touching Object.prototype', () => {
    for (const bad of ['__proto__', 'constructor', 'toString', 'zz']) {
      expect(() => op({ op: 'removeGuard', guard: bad } as any, { nonce })).toThrow(/x-only|no such guard|guard/);
      expect(() => op({ op: 'cancelGuardRemoval', guard: bad } as any, { nonce })).toThrow();
    }
    expect(({} as any).removableAt).toBeUndefined();
    expect(Object.prototype.hasOwnProperty.call(Object.prototype, 'removableAt')).toBe(false);
  });

  // Audit A3-2: the settings change delay has the same permanent floor.
  it('never lets the settings change delay go below the permanent minimums', () => {
    expect(() => op({ op: 'changePolicy', policy: { ...policy, policyDelay: 1 } }, { nonce })).toThrow(/settings change delay/);
  });

  // Audit A3-2 (second pass): the floor is both minimums in turn, and it holds
  // even for an account whose stored policyDelay predates the floor.
  it('a policy change waits at least both delay minimums', () => {
    const acct = signer.getAccount(hex(owner))!;
    const saved = acct.policy.policyDelay;
    acct.policy.policyDelay = 60; // an account registered before the floor
    const r = op({ op: 'changePolicy', policy: { ...acct.policy, policyDelay: 2 * DAY, maxFee: 10_000_000 } });
    expect(r.effectiveAt - clock).toBe(Math.max(acct.floors.withdrawalDelay + acct.floors.addressDelay, acct.policy.withdrawalDelay));
    op({ op: 'cancelPolicyChange' });
    acct.policy.policyDelay = saved;
    expect(() => op({ op: 'changePolicy', policy: { ...policy, policyDelay: DAY } }, { nonce })).toThrow(/settings change delay/);
  });

  // Audit A15-2: never sooner than the current withdrawal delay either, so a
  // raised delay (30 days over 1 + 7 day minimums) cannot be lowered in 8 days.
  it('a policy change waits at least the current withdrawal delay', () => {
    const acct = signer.getAccount(hex(owner))!;
    const saved = acct.policy.withdrawalDelay;
    acct.policy.withdrawalDelay = 30 * DAY;
    const r = op({ op: 'changePolicy', policy: { ...acct.policy, withdrawalDelay: acct.floors.withdrawalDelay } });
    expect(r.effectiveAt - clock).toBe(30 * DAY);
    op({ op: 'cancelPolicyChange' });
    acct.policy.withdrawalDelay = saved;
  });
});
