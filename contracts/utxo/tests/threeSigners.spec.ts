// Three independent signer services (own key, own state) co-sign 2-of-3.
import * as bitcoin from 'bitcoinjs-lib';
import * as ecc from '@bitcoinerlab/secp256k1';
import { ECPairFactory } from 'ecpair';
import * as bip39 from 'bip39';
import { createVault } from '../src/vault';
import { buildCosignedSpend, finalizeCosignedSpend, signSpend, Signer } from '../src/spend';
import { taprootSigner } from '../src/keys';
import { ownerAccountXpub, ownerKey } from '../src/mnemonicKeys';
import { Operation, Policy, signOperation, VaultConfig } from '../src/signer/messages';
import { SignerService } from '../src/signer/service';
import { Regtest } from './regtest';

const network = bitcoin.networks.regtest;
const ECPair = ECPairFactory(ecc);
const DAY = 86400;
const RESERVE = 10;
const FEE = 1_000;
const policy: Policy = { withdrawalDelay: DAY, addressDelay: DAY, policyDelay: 2 * DAY, confirmationWindow: DAY, maxFee: 10_000 };
const floors = { withdrawalDelay: DAY, addressDelay: DAY };
const key = (): Signer => { const kp = ECPair.makeRandom({ network }); return taprootSigner({ privateKey: kp.privateKey!, publicKey: Buffer.from(kp.publicKey) }); };
const hex = (k: Signer) => k.publicKey.toString('hex');

describe('three signers, 2-of-3 (regtest)', () => {
  const node = new Regtest();
  let clock = 1_900_000_000;
  const mnemonic = bip39.generateMnemonic(256);
  const owner = ownerKey(mnemonic, network);
  const keys = [key(), key(), key()];
  const signers = keys.map(k => new SignerService({ key: k, network, networkName: 'regtest', now: () => clock, sendSos: () => {} }));
  const nonces = [0, 0, 0];
  const op = (i: number, operation: Operation) => {
    const s = signers[i];
    return s.submit(signOperation({
      domain: s.domain, account: hex(owner), nonce: nonces[i]++, expiresAt: clock + 600,
      head: operation.op === 'register' ? undefined : s.getAccount(hex(owner))!.head.hash, operation,
    }, owner)) as any;
  };
  const all = (operation: Operation) => [0, 1, 2].map(i => op(i, operation));
  const head = (i: number) => signers[i].getAccount(hex(owner))!.head.hash;
  let destination: string;

  beforeAll(async () => { await node.start(); destination = await node.rpc('getnewaddress', ['', 'bech32m'], 'miner'); }, 60_000);
  afterAll(() => node.stop(), 30_000);

  it('a new vault: every signer registers the same 2-of-3 address; two of them co-sign a withdrawal', async () => {
    const config: VaultConfig = { generation: 0, owner: hex(owner), signers: keys.map(hex), threshold: 2, reserveBlocks: RESERVE };
    const regs = all({ op: 'register', accountXpub: ownerAccountXpub(mnemonic, network), vault: config, policy, floors });
    expect(new Set(regs.map((r: any) => r.address)).size).toBe(1);
    const vault = createVault({ owner: owner.publicKey, signers: keys.map(k => k.publicKey), threshold: 2, reserveBlocks: RESERVE, network });
    expect(regs[0].address).toBe(vault.address);

    all({ op: 'addAddress', address: destination });
    clock += DAY;
    const utxo = await node.fund(vault.address, 100_000);
    const reqs = all({ op: 'requestWithdrawal', to: destination, amount: 60_000 });
    clock += DAY;

    // Signers 0 and 2 (signer 1 is down): the PSBT uses their pair's leaf.
    const pair = [keys[0].publicKey, keys[2].publicKey];
    const psbt = buildCosignedSpend([{ vault, utxos: [utxo], signers: pair }], [{ address: destination, value: 60_000 }, { address: vault.address, value: 40_000 - FEE }], pair);
    signSpend(psbt, owner);
    let b64 = signers[0].signWithdrawal(hex(owner), head(0), reqs[0].id, psbt.toBase64());
    b64 = signers[2].signWithdrawal(hex(owner), head(2), reqs[2].id, b64);
    const tx = finalizeCosignedSpend(bitcoin.Psbt.fromBase64(b64, { network }), [vault]);
    expect(await node.test(tx.toHex())).toMatchObject({ allowed: true });
  });

  it('one signer alone cannot complete a withdrawal', async () => {
    const vault = createVault({ owner: owner.publicKey, signers: keys.map(k => k.publicKey), threshold: 2, reserveBlocks: RESERVE, network });
    const utxo = await node.fund(vault.address, 100_000);
    const reqs = all({ op: 'requestWithdrawal', to: destination, amount: 50_000 });
    clock += DAY;
    const pair = [keys[0].publicKey, keys[1].publicKey];
    const psbt = buildCosignedSpend([{ vault, utxos: [utxo], signers: pair }], [{ address: destination, value: 50_000 }, { address: vault.address, value: 50_000 - FEE }], pair);
    signSpend(psbt, owner);
    const b64 = signers[0].signWithdrawal(hex(owner), head(0), reqs[0].id, psbt.toBase64());
    expect(() => finalizeCosignedSpend(bitcoin.Psbt.fromBase64(b64, { network }), [vault])).toThrow(/missing a signature/);
  });

  it('an old one-signer vault moves to 2-of-3: policy change, new generation, renewal', async () => {
    // A separate owner whose vault has only signer 0.
    const m2 = bip39.generateMnemonic(256);
    const o2 = ownerKey(m2, network);
    const n2 = [0, 0, 0];
    const op2 = (i: number, operation: Operation) => {
      const s = signers[i];
      return s.submit(signOperation({ domain: s.domain, account: hex(o2), nonce: n2[i]++, expiresAt: clock + 600,
        head: operation.op === 'register' ? undefined : s.getAccount(hex(o2))!.head.hash, operation }, o2)) as any;
    };
    const oldConfig: VaultConfig = { generation: 0, owner: hex(o2), signers: [hex(keys[0])], threshold: 1, reserveBlocks: RESERVE };
    op2(0, { op: 'register', accountXpub: ownerAccountXpub(m2, network), vault: oldConfig, policy, floors });
    const oldVault = createVault({ owner: o2.publicKey, signers: [keys[0].publicKey], threshold: 1, reserveBlocks: RESERVE, network });
    const coin = await node.fund(oldVault.address, 100_000);

    // The set change waits the settings delay, like any policy change.
    const three = { ...policy, signers: keys.map(hex), threshold: 2 };
    expect(op2(0, { op: 'changePolicy', policy: three })).toMatchObject({ applied: false });
    expect(() => op2(0, { op: 'changePolicy', policy: { ...policy, signers: keys.map(hex), threshold: 1 } })).toThrow(/threshold/);
    n2[0]--; // the refused op did not consume the nonce
    clock += 2 * DAY + 1;
    op2(0, { op: 'applyPolicyChange' });

    // Signers 1 and 2 join: same identity, 2-of-3 terms.
    const gen0three: VaultConfig = { generation: 0, owner: hex(o2), signers: keys.map(hex), threshold: 2, reserveBlocks: RESERVE };
    for (const i of [1, 2]) op2(i, { op: 'register', accountXpub: ownerAccountXpub(m2, network), vault: gen0three, policy: three, floors });
    const gen1Key = ownerKey(m2, network, 1);
    const gen1: VaultConfig = { generation: 1, owner: hex(gen1Key), signers: keys.map(hex), threshold: 2, reserveBlocks: RESERVE };
    const addrs = [0, 1, 2].map(i => op2(i, { op: 'addGeneration', vault: gen1 }).address);
    expect(new Set(addrs).size).toBe(1);
    const newVault = createVault({ owner: gen1Key.publicKey, signers: keys.map(k => k.publicKey), threshold: 2, reserveBlocks: RESERVE, network });
    expect(addrs[0]).toBe(newVault.address);

    // Renewal: signer 0 co-signs moving the old coin into the 2-of-3 generation.
    const psbt = buildCosignedSpend([{ vault: oldVault, utxos: [coin], signers: [keys[0].publicKey] }], [{ address: newVault.address, value: 100_000 - FEE }], keys[0].publicKey);
    signSpend(psbt, o2);
    const b64 = signers[0].signRefresh(hex(o2), signers[0].getAccount(hex(o2))!.head.hash, psbt.toBase64());
    const tx = finalizeCosignedSpend(bitcoin.Psbt.fromBase64(b64, { network }), [oldVault, newVault]);
    expect(await node.test(tx.toHex())).toMatchObject({ allowed: true });
  });
});
