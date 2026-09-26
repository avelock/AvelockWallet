// Building, signing and finalizing vault spends (PSBT, BIP-174/371).

import * as bitcoin from 'bitcoinjs-lib';
import { Door, Vault, signerSet, spendInfo } from './vault';

export interface VaultUtxo {
  txid: string;
  vout: number;
  value: number;
}

export interface Output {
  address: string;
  value: number;
}

export interface Signer {
  /** 32-byte x-only public key. */
  publicKey: Buffer;
  signSchnorr(hash: Buffer): Buffer;
}

/**
 * An unsigned spend through one door. Timelocked doors set the input
 * sequence to the door's CSV value, so the transaction is only valid once
 * each input has that many confirmations.
 */
export function buildSpend(vault: Vault, door: Door, utxos: VaultUtxo[], outputs: Output[], signer?: Buffer | Buffer[]): bitcoin.Psbt {
  const { leaf, controlBlock } = spendInfo(vault, door, signer);
  const sequence = door === 'reserve' ? vault.params.reserveBlocks
    : door === 'heir' ? vault.params.heirBlocks!
    : 0xfffffffd; // RBF-enabled, no relative lock
  const psbt = new bitcoin.Psbt({ network: vault.params.network });
  psbt.setVersion(2); // BIP-68 relative locktimes require version >= 2
  for (const u of utxos) {
    psbt.addInput({
      hash: u.txid,
      index: u.vout,
      sequence,
      witnessUtxo: { script: vault.output, value: u.value },
      tapLeafScript: [{ leafVersion: leaf.leafVersion, script: leaf.script, controlBlock }],
    });
  }
  for (const o of outputs) psbt.addOutput({ address: o.address, value: o.value });
  return psbt;
}

/**
 * An unsigned cosigned-door spend whose inputs may come from several
 * vaults (generations); each input carries its own vault's leaf.
 */
export function buildCosignedSpend(parts: CosignedPart[], outputs: Output[], signer: Buffer | Buffer[]): bitcoin.Psbt {
  if (parts.length === 0) throw new Error('no inputs');
  const psbt = new bitcoin.Psbt({ network: parts[0].vault.params.network });
  psbt.setVersion(2);
  for (const { vault, utxos, signers } of parts) {
    const { leaf, controlBlock } = spendInfo(vault, 'cosigned', signers ?? signer);
    for (const u of utxos) {
      psbt.addInput({
        hash: u.txid, index: u.vout, sequence: 0xfffffffd,
        witnessUtxo: { script: vault.output, value: u.value },
        tapLeafScript: [{ leafVersion: leaf.leafVersion, script: leaf.script, controlBlock }],
      });
    }
  }
  for (const o of outputs) psbt.addOutput({ address: o.address, value: o.value });
  return psbt;
}

/**
 * Adds this key's Schnorr signature to every input whose leaf script
 * contains the key (in a multi-generation spend each owner key signs only
 * its own generation's inputs). Throws if it signed nothing.
 */
export function signSpend(psbt: bitcoin.Psbt, key: Signer): void {
  // Script-path spends only need Schnorr; ECDSA `sign` is never called.
  const adapter = { ...key, sign: () => { throw new Error('ECDSA signing is not supported'); } };
  let signed = 0;
  psbt.data.inputs.forEach((input, i) => {
    const leaf = input.tapLeafScript?.[0];
    if (leaf && leaf.script.includes(key.publicKey)) {
      psbt.signTaprootInput(i, adapter);
      signed++;
    }
  });
  if (signed === 0) throw new Error('this key cannot sign any input');
}

/**
 * Finalizes a cosigned-door spend whose inputs may span several vaults and
 * several signer sets (a renewal moves 1-signer generations into a 2-of-3
 * one). Each input is finalized from the leaf it carries: the keys are read
 * from the leaf script (owner first, then its signers), and the input must
 * belong to one of `vaults` with that leaf as a cosigned door.
 */
export function finalizeCosignedSpend(psbt: bitcoin.Psbt, vaults: Vault[], _signers?: Buffer | Buffer[]): bitcoin.Transaction {
  psbt.data.inputs.forEach((input, i) => {
    const vault = vaults.find(v => input.witnessUtxo?.script.equals(v.output));
    if (!vault) throw new Error(`input ${i} is not from a known vault`);
    const carried = input.tapLeafScript?.[0];
    const leaf = carried && vault.leaves.find(l => l.door === 'cosigned' && l.script.equals(carried.script));
    if (!leaf) throw new Error(`input ${i} does not spend a cosigned door of its vault`);
    const { controlBlock } = spendInfo(vault, 'cosigned', leaf.signers);
    const leafHash = bitcoin.crypto.taggedHash('TapLeaf', Buffer.concat([Buffer.from([leaf.leafVersion]), varSlice(leaf.script)]));
    const sig = (pubkey: Buffer) => {
      const s = (input.tapScriptSig ?? []).find(x => x.pubkey.equals(pubkey) && x.leafHash.equals(leafHash));
      if (!s) throw new Error(`input ${i} is missing a signature from ${pubkey.toString('hex')}`);
      return s.signature;
    };
    // The script checks the owner first, then the signers in order: the
    // first key checked must be on top of the stack.
    const stack = [...[...leaf.signers!].reverse().map(sig), sig(vault.params.owner)];
    psbt.finalizeInput(i, () => ({ finalScriptWitness: witnessStackToScriptWitness([...stack, leaf.script, controlBlock]) }));
  });
  return psbt.extractTransaction();
}

/** A cosigned spend part: its vault, coins, and the signer subset whose leaf it uses. */
export type CosignedPart = { vault: Vault; utxos: VaultUtxo[]; signers?: Buffer | Buffer[] };

/**
 * Finalizes every input. For the cosigned door the script checks the owner
 * signature first, so it must sit on top of the stack: witness order is
 * [signerSig, ownerSig, script, controlBlock].
 */
export function finalizeSpend(psbt: bitcoin.Psbt, vault: Vault, door: Door, signer?: Buffer | Buffer[]): bitcoin.Transaction {
  const { leaf, controlBlock } = spendInfo(vault, door, signer);
  const leafHash = bitcoin.crypto.taggedHash('TapLeaf', Buffer.concat([
    Buffer.from([leaf.leafVersion]), varSlice(leaf.script),
  ]));
  const order = door === 'cosigned' ? [...signerSet(signer).reverse(), vault.params.owner]
    : door === 'reserve' ? [vault.params.owner]
    : [vault.params.heir!];
  for (let i = 0; i < psbt.inputCount; i++) {
    const sigs = psbt.data.inputs[i].tapScriptSig ?? [];
    const stack = order.map(pubkey => {
      const s = sigs.find(x => x.pubkey.equals(pubkey) && x.leafHash.equals(leafHash));
      if (!s) throw new Error(`input ${i} is missing a signature from ${pubkey.toString('hex')}`);
      return s.signature;
    });
    psbt.finalizeInput(i, () => ({
      finalScriptWitness: witnessStackToScriptWitness([...stack, leaf.script, controlBlock]),
    }));
  }
  return psbt.extractTransaction();
}

function varSlice(buf: Buffer): Buffer {
  return Buffer.concat([varint(buf.length), buf]);
}

function varint(n: number): Buffer {
  if (n < 0xfd) return Buffer.from([n]);
  if (n <= 0xffff) { const b = Buffer.alloc(3); b[0] = 0xfd; b.writeUInt16LE(n, 1); return b; }
  const b = Buffer.alloc(5); b[0] = 0xfe; b.writeUInt32LE(n, 1); return b;
}

function witnessStackToScriptWitness(stack: Buffer[]): Buffer {
  return Buffer.concat([varint(stack.length), ...stack.map(varSlice)]);
}
