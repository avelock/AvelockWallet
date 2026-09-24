// ============================================================
// Avelock Wallet — Bitcoin vault
// Self-custody vault with on-chain withdrawal delays.
// https://github.com/avelock/AvelockWallet
// ============================================================
//
// A Bitcoin vault is a Taproot output with no usable key path (the
// internal key is the BIP-341 NUMS point, whose secret nobody knows) and
// one script leaf per "door" (see BITCOIN_DESIGN.md):
//
//   cosigned  owner + one signer        immediately; the signer enforces
//                                       delays/allowlist off-chain
//   reserve   owner alone               after `reserveBlocks` (CSV)
//   heir      inheritance key alone     after `heirBlocks` (CSV), optional
//
// CSV is relative to the confirmation of each UTXO, so the vault must be
// refreshed (moved to a new vault address) before `reserveBlocks` elapse.

import * as bitcoin from 'bitcoinjs-lib';
import * as ecc from '@bitcoinerlab/secp256k1';
import type { Taptree } from 'bitcoinjs-lib/src/types';

bitcoin.initEccLib(ecc);

/** BIP-341 NUMS point: x-only key with no known discrete log. */
export const NUMS_INTERNAL_KEY = Buffer.from(
  '50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0',
  'hex',
);

/** BIP-68 block-based relative locktime is a 16-bit value. */
export const MAX_CSV_BLOCKS = 0xffff;

export type Door = 'cosigned' | 'reserve' | 'heir';

export interface VaultParams {
  /** 32-byte x-only owner key. */
  owner: Buffer;
  /** 32-byte x-only signer keys; the cosigned door accepts any one of them. */
  signers: Buffer[];
  /** Blocks after which the owner alone may spend. */
  reserveBlocks: number;
  /** Optional 32-byte x-only inheritance key. */
  heir?: Buffer;
  /** Blocks after which the heir key alone may spend; must exceed reserveBlocks. */
  heirBlocks?: number;
  network: bitcoin.Network;
}

export interface Leaf {
  door: Door;
  /** For cosigned leaves: which signer key this leaf pairs with the owner. */
  signer?: Buffer;
  script: Buffer;
  leafVersion: number;
}

export interface Vault {
  params: VaultParams;
  address: string;
  output: Buffer;
  leaves: Leaf[];
  scriptTree: Taptree;
}

const LEAF_VERSION = 0xc0;

function assertXOnly(key: Buffer, name: string) {
  if (key.length !== 32 || !ecc.isXOnlyPoint(key)) throw new Error(`${name} must be a 32-byte x-only public key`);
}

function assertBlocks(value: number, name: string) {
  if (!Number.isInteger(value) || value < 1 || value > MAX_CSV_BLOCKS) {
    throw new Error(`${name} must be an integer between 1 and ${MAX_CSV_BLOCKS} blocks`);
  }
}

/** <owner> CHECKSIGVERIFY <signer> CHECKSIG — witness: [signerSig, ownerSig]. */
export function cosignedScript(owner: Buffer, signer: Buffer): Buffer {
  return bitcoin.script.compile([
    owner, bitcoin.opcodes.OP_CHECKSIGVERIFY,
    signer, bitcoin.opcodes.OP_CHECKSIG,
  ]);
}

/** <blocks> CSV DROP <key> CHECKSIG — witness: [sig]. */
export function timelockedScript(key: Buffer, blocks: number): Buffer {
  return bitcoin.script.compile([
    bitcoin.script.number.encode(blocks), bitcoin.opcodes.OP_CHECKSEQUENCEVERIFY, bitcoin.opcodes.OP_DROP,
    key, bitcoin.opcodes.OP_CHECKSIG,
  ]);
}

function toTree(leaves: Leaf[]): Taptree {
  const nodes: Taptree[] = leaves.map(l => ({ output: l.script, version: l.leafVersion }));
  // Balanced-ish tree: pair adjacent nodes until one root remains.
  let level = nodes;
  while (level.length > 1) {
    const next: Taptree[] = [];
    for (let i = 0; i < level.length; i += 2) {
      next.push(i + 1 < level.length ? [level[i], level[i + 1]] : level[i]);
    }
    level = next;
  }
  return level[0];
}

export function createVault(params: VaultParams): Vault {
  assertXOnly(params.owner, 'owner');
  if (params.signers.length < 1) throw new Error('at least one signer is required');
  // Canonical order: the same key set always yields the same address.
  params = { ...params, signers: [...params.signers].sort(Buffer.compare) };
  params.signers.forEach((s, i) => assertXOnly(s, `signers[${i}]`));
  const distinct = new Set([params.owner, ...params.signers, ...(params.heir ? [params.heir] : [])].map(k => k.toString('hex')));
  if (distinct.size !== 1 + params.signers.length + (params.heir ? 1 : 0)) {
    throw new Error('owner, signer and heir keys must all be different');
  }
  assertBlocks(params.reserveBlocks, 'reserveBlocks');
  if ((params.heir == null) !== (params.heirBlocks == null)) throw new Error('heir and heirBlocks go together');
  if (params.heir) {
    assertXOnly(params.heir, 'heir');
    assertBlocks(params.heirBlocks!, 'heirBlocks');
    // The living owner's reserve door must always open before the heir's.
    if (params.heirBlocks! <= params.reserveBlocks) throw new Error('heirBlocks must be greater than reserveBlocks');
  }

  const leaves: Leaf[] = [
    ...params.signers.map(signer => ({ door: 'cosigned' as const, signer, script: cosignedScript(params.owner, signer), leafVersion: LEAF_VERSION })),
    { door: 'reserve', script: timelockedScript(params.owner, params.reserveBlocks), leafVersion: LEAF_VERSION },
    ...(params.heir ? [{ door: 'heir' as const, script: timelockedScript(params.heir, params.heirBlocks!), leafVersion: LEAF_VERSION }] : []),
  ];
  const scriptTree = toTree(leaves);
  const payment = bitcoin.payments.p2tr({ internalPubkey: NUMS_INTERNAL_KEY, scriptTree, network: params.network });
  return { params, address: payment.address!, output: payment.output!, leaves, scriptTree };
}

/** The leaf and control block needed to spend through one door. */
export function spendInfo(vault: Vault, door: Door, signer?: Buffer) {
  const leaf = vault.leaves.find(l => l.door === door && (door !== 'cosigned' || (signer != null && l.signer!.equals(signer))));
  if (!leaf) throw new Error(`vault has no ${door} door${signer ? ' for this signer' : ''}`);
  const redeem = { output: leaf.script, redeemVersion: leaf.leafVersion };
  const payment = bitcoin.payments.p2tr({
    internalPubkey: NUMS_INTERNAL_KEY, scriptTree: vault.scriptTree, redeem, network: vault.params.network,
  });
  const controlBlock = payment.witness![payment.witness!.length - 1];
  return { leaf, controlBlock };
}
