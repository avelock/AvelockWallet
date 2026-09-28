// 2-of-3 cosigned door on regtest: owner + any two of three signers.
import * as bitcoin from 'bitcoinjs-lib';
import * as ecc from '@bitcoinerlab/secp256k1';
import { ECPairFactory } from 'ecpair';
import * as bip39 from 'bip39';
import { combinations, cosignedScript, createVault, Vault } from '../src/vault';
import { buildCosignedSpend, buildSpend, finalizeCosignedSpend, finalizeSpend, signSpend, Signer } from '../src/spend';
import { taprootSigner } from '../src/keys';
import { ownerKey } from '../src/mnemonicKeys';
import { Regtest } from './regtest';

const network = bitcoin.networks.regtest;
const ECPair = ECPairFactory(ecc);
const RESERVE = 10;
const FEE = 1_000;
const randomKey = (): Signer => {
  const kp = ECPair.makeRandom({ network });
  return taprootSigner({ privateKey: kp.privateKey!, publicKey: Buffer.from(kp.publicKey) });
};

describe('2-of-3 vault (regtest)', () => {
  const node = new Regtest();
  const owner = ownerKey(bip39.generateMnemonic(256), network);
  const [a, b, c] = [randomKey(), randomKey(), randomKey()];
  let vault: Vault;
  let destination: string;

  beforeAll(async () => {
    await node.start();
    destination = await node.rpc('getnewaddress', ['', 'bech32m'], 'miner');
    vault = createVault({ owner: owner.publicKey, signers: [a.publicKey, b.publicKey, c.publicKey], threshold: 2, reserveBlocks: RESERVE, network });
  }, 60_000);
  afterAll(() => node.stop(), 30_000);

  it('has one cosigned leaf per pair of signers plus the reserve door', () => {
    expect(vault.leaves.map(l => l.door)).toEqual(['cosigned', 'cosigned', 'cosigned', 'reserve']);
    expect(combinations([1, 2, 3], 2)).toEqual([[1, 2], [1, 3], [2, 3]]);
  });

  it('a one-signer vault keeps its original leaf and address', () => {
    const one = createVault({ owner: owner.publicKey, signers: [a.publicKey], threshold: 1, reserveBlocks: RESERVE, network });
    const explicit = createVault({ owner: owner.publicKey, signers: [a.publicKey], threshold: 1, reserveBlocks: RESERVE, network });
    expect(one.address).toBe(explicit.address);
    const legacy = bitcoin.script.compile([owner.publicKey, bitcoin.opcodes.OP_CHECKSIGVERIFY, a.publicKey, bitcoin.opcodes.OP_CHECKSIG]);
    expect(one.leaves[0].script.equals(legacy)).toBe(true);
    expect(cosignedScript(owner.publicKey, a.publicKey).equals(legacy)).toBe(true);
  });

  it.each([[0, 1], [0, 2], [1, 2]])('owner + signers %i and %i spend at once', async (i, j) => {
    const pair = [a, b, c].filter((_, k) => k === i || k === j);
    const utxo = await node.fund(vault.address, 100_000);
    const psbt = buildSpend(vault, 'cosigned', [utxo], [{ address: destination, value: 100_000 - FEE }], pair.map(s => s.publicKey));
    signSpend(psbt, owner);
    pair.forEach(s => signSpend(psbt, s));
    const tx = finalizeSpend(psbt, vault, 'cosigned', pair.map(s => s.publicKey));
    expect(await node.test(tx.toHex())).toMatchObject({ allowed: true });
  });

  it('owner + one signer cannot spend', async () => {
    const utxo = await node.fund(vault.address, 100_000);
    const psbt = buildSpend(vault, 'cosigned', [utxo], [{ address: destination, value: 100_000 - FEE }], [a.publicKey, b.publicKey]);
    signSpend(psbt, owner);
    signSpend(psbt, a);
    expect(() => finalizeSpend(psbt, vault, 'cosigned', [a.publicKey, b.publicKey])).toThrow(/missing a signature/);
    // Forging the second signature with a key that is not in the leaf fails in consensus.
    const forged = psbt.data.inputs[0].tapScriptSig!.find(s => s.pubkey.equals(a.publicKey))!;
    psbt.updateInput(0, { tapScriptSig: [{ ...forged, pubkey: b.publicKey }] });
    const tx = finalizeSpend(psbt, vault, 'cosigned', [a.publicKey, b.publicKey]);
    expect((await node.test(tx.toHex())).allowed).toBe(false);
  });

  it('a renewal moves a one-signer generation into the 2-of-3 one', async () => {
    const old = createVault({ owner: owner.publicKey, signers: [a.publicKey], threshold: 1, reserveBlocks: RESERVE, network });
    const utxo = await node.fund(old.address, 100_000);
    const psbt = buildCosignedSpend([{ vault: old, utxos: [utxo], signers: [a.publicKey] }], [{ address: vault.address, value: 100_000 - FEE }], a.publicKey);
    signSpend(psbt, owner);
    signSpend(psbt, a);
    const tx = finalizeCosignedSpend(psbt, [old, vault]);
    expect(await node.test(tx.toHex())).toMatchObject({ allowed: true });
  });

  it('the reserve door still opens for the owner alone after reserveBlocks', async () => {
    const utxo = await node.fund(vault.address, 100_000);
    await node.mine(RESERVE);
    const psbt = buildSpend(vault, 'reserve', [utxo], [{ address: destination, value: 100_000 - FEE }]);
    signSpend(psbt, owner);
    expect(await node.test(finalizeSpend(psbt, vault, 'reserve').toHex())).toMatchObject({ allowed: true });
  });
});
