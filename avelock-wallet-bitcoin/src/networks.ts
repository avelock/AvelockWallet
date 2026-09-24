// Networks beyond bitcoinjs-lib's built-ins. Litecoin has Taproot (since
// Litecoin Core 0.21.2), so the same vault scripts work there.

import * as bitcoin from 'bitcoinjs-lib';

export const litecoin: bitcoin.Network = {
  messagePrefix: '\x19Litecoin Signed Message:\n',
  bech32: 'ltc',
  bip32: { public: 0x0488b21e, private: 0x0488ade4 },
  pubKeyHash: 0x30,
  scriptHash: 0x32,
  wif: 0xb0,
};

export const litecoinTestnet: bitcoin.Network = {
  messagePrefix: '\x19Litecoin Signed Message:\n',
  bech32: 'tltc',
  bip32: { public: 0x043587cf, private: 0x04358394 },
  pubKeyHash: 0x6f,
  scriptHash: 0x3a,
  wif: 0xef,
};

/**
 * SLIP-44 coin type for key paths: 0 = Bitcoin, 1 = Bitcoin test networks,
 * 2 = Litecoin (mainnet and testnet, so Litecoin keys never equal Bitcoin
 * test keys from the same seed).
 */
export function coinType(network: bitcoin.Network): number {
  if (network.bech32 === 'ltc' || network.bech32 === 'tltc') return 2;
  return network === bitcoin.networks.bitcoin ? 0 : 1;
}
