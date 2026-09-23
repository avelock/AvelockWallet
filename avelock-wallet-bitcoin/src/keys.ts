// Owner and inheritance keys derived from BIP-39 mnemonics.
//
// Owner vault keys use a dedicated BIP-86-style account so they never
// collide with an ordinary single-key Taproot wallet on the same seed:
//
//   m/86'/<coin>'/100'/0/<generation>
//
// <coin> is 0 on mainnet and 1 on test networks. <generation> increments
// on every vault refresh, so each refresh gets a new vault address and a
// wallet can rediscover all generations by scanning upward from 0.
// Signer keys are never derived from the owner's seed.

import * as bitcoin from 'bitcoinjs-lib';
import * as ecc from '@bitcoinerlab/secp256k1';
import { BIP32Factory, BIP32Interface } from 'bip32';
import * as bip39 from 'bip39';
import type { Signer } from './spend';

const bip32 = BIP32Factory(ecc);

export const OWNER_ACCOUNT = 100;

export function ownerPath(network: bitcoin.Network, generation: number): string {
  const coin = network === bitcoin.networks.bitcoin ? 0 : 1;
  return `m/86'/${coin}'/${OWNER_ACCOUNT}'/0/${generation}`;
}

// The *FromSeed variants take BIP-39 seed bytes, so a client that already
// derives the seed natively (the mobile app) doesn't repeat PBKDF2 in JS.

/** Account-level xpub (m/86'/<coin>'/100'); generation keys are its public children 0/<generation>. */
export function ownerAccountXpubFromSeed(seed: Uint8Array, network: bitcoin.Network): string {
  const coin = network === bitcoin.networks.bitcoin ? 0 : 1;
  const root = bip32.fromSeed(Buffer.from(seed), network);
  return root.derivePath(`m/86'/${coin}'/${OWNER_ACCOUNT}'`).neutered().toBase58();
}

export function ownerKeyFromSeed(seed: Uint8Array, network: bitcoin.Network, generation = 0): Signer {
  const root = bip32.fromSeed(Buffer.from(seed), network);
  return taprootSigner(root.derivePath(ownerPath(network, generation)));
}

export function ownerAccountXpub(mnemonic: string, network: bitcoin.Network): string {
  if (!bip39.validateMnemonic(mnemonic)) throw new Error('invalid mnemonic');
  return ownerAccountXpubFromSeed(bip39.mnemonicToSeedSync(mnemonic), network);
}

/** x-only owner key of a generation, derived from the account xpub alone. */
export function ownerPublicKey(accountXpub: string, network: bitcoin.Network, generation: number): Buffer {
  if (!Number.isInteger(generation) || generation < 0 || generation >= 0x80000000) throw new Error('invalid generation');
  const node = bip32.fromBase58(accountXpub, network);
  if (node.depth !== 3 || node.privateKey) throw new Error('expected a neutered account-level xpub');
  return Buffer.from(node.derive(0).derive(generation).publicKey.subarray(1, 33));
}

export function ownerKey(mnemonic: string, network: bitcoin.Network, generation = 0): Signer {
  if (!bip39.validateMnemonic(mnemonic)) throw new Error('invalid mnemonic');
  return ownerKeyFromSeed(bip39.mnemonicToSeedSync(mnemonic), network, generation);
}

/** Standard BIP-86 key (m/86'/<coin>'/0'/0/0) for an inheritance-sheet wallet. */
export function heirKey(mnemonic: string, network: bitcoin.Network): Signer {
  if (!bip39.validateMnemonic(mnemonic)) throw new Error('invalid mnemonic');
  const coin = network === bitcoin.networks.bitcoin ? 0 : 1;
  const root = bip32.fromSeed(bip39.mnemonicToSeedSync(mnemonic), network);
  return taprootSigner(root.derivePath(`m/86'/${coin}'/0'/0/0`));
}

/**
 * Script-path signer: Schnorr-signs with the untweaked private key, which
 * is what OP_CHECKSIG inside a tapscript leaf verifies against the
 * leaf's x-only key.
 */
export function taprootSigner(node: Pick<BIP32Interface, 'privateKey' | 'publicKey'>): Signer {
  if (!node.privateKey) throw new Error('private key required');
  const privateKey = node.privateKey;
  return {
    publicKey: Buffer.from(node.publicKey.subarray(1, 33)),
    signSchnorr: (hash: Buffer) => Buffer.from(ecc.signSchnorr(hash, privateKey)),
  };
}
