import * as bitcoin from 'bitcoinjs-lib';
import * as ecc from '@bitcoinerlab/secp256k1';
import { ECPairFactory } from 'ecpair';
import * as bip39 from 'bip39';
import { createVault, Vault } from '../src/vault';
import { buildSpend, finalizeSpend, signSpend, Signer } from '../src/spend';
import { taprootSigner } from '../src/keys';
import { heirKey, ownerKey } from '../src/mnemonicKeys';
import { Regtest } from './regtest';

const network = bitcoin.networks.regtest;
const ECPair = ECPairFactory(ecc);
const RESERVE = 10;
const HEIR = 20;
const FEE = 1_000;

function randomKey(): Signer {
  const kp = ECPair.makeRandom({ network });
  return taprootSigner({ privateKey: kp.privateKey!, publicKey: Buffer.from(kp.publicKey) });
}

describe('Bitcoin vault (regtest)', () => {
  const node = new Regtest();
  const ownerMnemonic = bip39.generateMnemonic(256);
  const owner = ownerKey(ownerMnemonic, network);
  const signer = randomKey();
  const heir = heirKey(bip39.generateMnemonic(256), network);
  let vault: Vault;
  let destination: string;

  beforeAll(async () => {
    await node.start();
    destination = await node.rpc('getnewaddress', ['', 'bech32m'], 'miner');
    vault = createVault({
      owner: owner.publicKey, signers: [signer.publicKey], threshold: 1, reserveBlocks: RESERVE,
      heir: heir.publicKey, heirBlocks: HEIR, network,
    });
  }, 60_000);

  afterAll(() => node.stop(), 30_000);

  it('produces a Taproot address with no usable key path', () => {
    expect(vault.address.startsWith('bcrt1p')).toBe(true);
    expect(vault.leaves.map(l => l.door)).toEqual(['cosigned', 'reserve', 'heir']);
  });

  it('owner + signer spend immediately (cosigned door)', async () => {
    const utxo = await node.fund(vault.address, 100_000);
    const psbt = buildSpend(vault, 'cosigned', [utxo], [{ address: destination, value: 100_000 - FEE }], signer.publicKey);
    signSpend(psbt, owner);
    signSpend(psbt, signer);
    const tx = finalizeSpend(psbt, vault, 'cosigned', signer.publicKey);
    expect(await node.test(tx.toHex())).toMatchObject({ allowed: true });
  });

  it('owner alone cannot use the cosigned door', async () => {
    const utxo = await node.fund(vault.address, 100_000);
    const psbt = buildSpend(vault, 'cosigned', [utxo], [{ address: destination, value: 100_000 - FEE }], signer.publicKey);
    signSpend(psbt, owner);
    expect(() => finalizeSpend(psbt, vault, 'cosigned', signer.publicKey)).toThrow(/missing a signature/);
  });

  it('a stolen owner key cannot fake the signer signature', async () => {
    const utxo = await node.fund(vault.address, 100_000);
    const psbt = buildSpend(vault, 'cosigned', [utxo], [{ address: destination, value: 100_000 - FEE }], signer.publicKey);
    signSpend(psbt, owner);
    // Attacker signs with the owner key but presents it as the signer's.
    const fake = psbt.data.inputs[0].tapScriptSig![0];
    psbt.updateInput(0, { tapScriptSig: [{ ...fake, pubkey: signer.publicKey }] });
    const tx = finalizeSpend(psbt, vault, 'cosigned', signer.publicKey);
    expect((await node.test(tx.toHex())).allowed).toBe(false);
  });

  it('the reserve door opens for the owner alone only after reserveBlocks', async () => {
    const utxo = await node.fund(vault.address, 100_000); // 1 confirmation
    const build = () => {
      const psbt = buildSpend(vault, 'reserve', [utxo], [{ address: destination, value: 100_000 - FEE }]);
      signSpend(psbt, owner);
      return finalizeSpend(psbt, vault, 'reserve').toHex();
    };
    expect(await node.test(build())).toMatchObject({ allowed: false, 'reject-reason': 'non-BIP68-final' });
    await node.mine(RESERVE - 2); // RESERVE - 1 confirmations
    expect(await node.test(build())).toMatchObject({ allowed: false, 'reject-reason': 'non-BIP68-final' });
    await node.mine(1); // RESERVE confirmations
    expect(await node.test(build())).toMatchObject({ allowed: true });
  });

  it('the heir door opens only after heirBlocks, later than the reserve door', async () => {
    const utxo = await node.fund(vault.address, 100_000);
    const build = () => {
      const psbt = buildSpend(vault, 'heir', [utxo], [{ address: destination, value: 100_000 - FEE }]);
      signSpend(psbt, heir);
      return finalizeSpend(psbt, vault, 'heir').toHex();
    };
    await node.mine(RESERVE); // reserve door is open, heir door is not
    expect(await node.test(build())).toMatchObject({ allowed: false, 'reject-reason': 'non-BIP68-final' });
    await node.mine(HEIR - RESERVE - 1);
    expect(await node.test(build())).toMatchObject({ allowed: true });
  });

  it('the signer alone cannot spend through any door', async () => {
    const utxo = await node.fund(vault.address, 100_000);
    await node.mine(HEIR);
    for (const door of ['reserve', 'heir'] as const) {
      const psbt = buildSpend(vault, door, [utxo], [{ address: destination, value: 100_000 - FEE }]);
      expect(() => signSpend(psbt, signer)).toThrow();
    }
  });

  it('a refresh to a new vault generation restarts the reserve timer', async () => {
    const utxo = await node.fund(vault.address, 100_000);
    await node.mine(RESERVE); // old UTXO: the reserve door is already open
    const nextOwner = ownerKey(ownerMnemonic, network, 1);
    const next = createVault({ ...vault.params, owner: nextOwner.publicKey });
    const psbt = buildSpend(vault, 'cosigned', [utxo], [{ address: next.address, value: 100_000 - FEE }], signer.publicKey);
    signSpend(psbt, owner);
    signSpend(psbt, signer);
    const refreshTxid = await node.broadcast(finalizeSpend(psbt, vault, 'cosigned', signer.publicKey).toHex());
    await node.mine(1);
    expect(refreshTxid).toHaveLength(64);
    // The refreshed UTXO has 1 confirmation, so the reserve door is closed again.
    const moved = { txid: refreshTxid, vout: 0, value: 100_000 - FEE };
    const build = () => {
      const psbt = buildSpend(next, 'reserve', [moved], [{ address: destination, value: moved.value - FEE }]);
      signSpend(psbt, nextOwner);
      return finalizeSpend(psbt, next, 'reserve').toHex();
    };
    expect(await node.test(build())).toMatchObject({ allowed: false, 'reject-reason': 'non-BIP68-final' });
    await node.mine(RESERVE - 1);
    expect(await node.test(build())).toMatchObject({ allowed: true });
  });

  it('with two signers, either one can cosign with the owner', async () => {
    const second = randomKey();
    const dual = createVault({ owner: owner.publicKey, signers: [signer.publicKey, second.publicKey], threshold: 1, reserveBlocks: RESERVE, network });
    for (const s of [signer, second]) {
      const utxo = await node.fund(dual.address, 50_000);
      const psbt = buildSpend(dual, 'cosigned', [utxo], [{ address: destination, value: 50_000 - FEE }], s.publicKey);
      signSpend(psbt, owner);
      signSpend(psbt, s);
      expect(await node.test(finalizeSpend(psbt, dual, 'cosigned', s.publicKey).toHex())).toMatchObject({ allowed: true });
    }
  });

  it('refuses several signers without a stated threshold (A10-2)', () => {
    const second = randomKey();
    expect(() => createVault({ owner: owner.publicKey, signers: [signer.publicKey, second.publicKey], reserveBlocks: RESERVE, network } as any))
      .toThrow('threshold must be between');
  });

  it('derives the same vault from the same seed (recovery)', () => {
    const again = createVault({ ...vault.params, owner: ownerKey(ownerMnemonic, network).publicKey });
    expect(again.address).toBe(vault.address);
  });

  it('gives the same address regardless of signer order', () => {
    const second = randomKey();
    const a = createVault({ owner: owner.publicKey, signers: [signer.publicKey, second.publicKey], threshold: 2, reserveBlocks: RESERVE, network });
    const b = createVault({ owner: owner.publicKey, signers: [second.publicKey, signer.publicKey], threshold: 2, reserveBlocks: RESERVE, network });
    expect(a.address).toBe(b.address);
  });

  it('rejects unsafe vault parameters', () => {
    const base = { owner: owner.publicKey, signers: [signer.publicKey], threshold: 1, reserveBlocks: RESERVE, network };
    expect(() => createVault({ ...base, heir: heir.publicKey, heirBlocks: RESERVE })).toThrow(/greater than reserveBlocks/);
    expect(() => createVault({ ...base, signers: [owner.publicKey] })).toThrow(/different/);
    expect(() => createVault({ ...base, reserveBlocks: 0x10000 })).toThrow(/between/);
    expect(() => createVault({ ...base, signers: [] })).toThrow(/at least one signer/);
  });
});
