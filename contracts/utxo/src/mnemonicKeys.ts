// Mnemonic-based key helpers for tests, scripts and the signer tools. The
// mobile app derives the seed natively and uses the *FromSeed functions in
// keys.ts, so it never bundles bip39 (audit P-12).

import * as bitcoin from 'bitcoinjs-lib';
import * as bip39 from 'bip39';
import type { Signer } from './spend';
import { coinType } from './networks';
import { bip32, ownerAccountXpubFromSeed, ownerKeyFromSeed, taprootSigner } from './keys';

export function ownerAccountXpub(mnemonic: string, network: bitcoin.Network): string {
  if (!bip39.validateMnemonic(mnemonic)) throw new Error('invalid mnemonic');
  return ownerAccountXpubFromSeed(bip39.mnemonicToSeedSync(mnemonic), network);
}

export function ownerKey(mnemonic: string, network: bitcoin.Network, generation = 0): Signer {
  if (!bip39.validateMnemonic(mnemonic)) throw new Error('invalid mnemonic');
  return ownerKeyFromSeed(bip39.mnemonicToSeedSync(mnemonic), network, generation);
}

/** Standard BIP-86 key (m/86'/<coin>'/0'/0/0) for an inheritance-sheet wallet. */
export function heirKey(mnemonic: string, network: bitcoin.Network): Signer {
  if (!bip39.validateMnemonic(mnemonic)) throw new Error('invalid mnemonic');
  const coin = coinType(network);
  const root = bip32.fromSeed(bip39.mnemonicToSeedSync(mnemonic), network);
  return taprootSigner(root.derivePath(`m/86'/${coin}'/0'/0/0`));
}
