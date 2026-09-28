// Minimal hand-rolled Anchor 0.30 wire-format helpers (instruction
// discriminators, account discriminators, borsh-style arg encoding and
// account decoding) written directly against programs/avelock_wallet/
// src/{lib.rs,state.rs} — used instead of the generated IDL/Program
// client, since IDL generation is currently broken in this environment
// (see README.md's toolchain notes). The Option<Account> sentinel
// convention (push the program's own ID, readonly, when None) was
// confirmed by reading anchor-syn 0.30.1's to_account_metas.rs /
// try_accounts.rs source directly rather than guessed.

import * as crypto from 'crypto';
import { PublicKey } from '@solana/web3.js';

export function discriminator(namespace: string, name: string): Buffer {
  const preimage = `${namespace}:${name}`;
  return crypto.createHash('sha256').update(preimage).digest().subarray(0, 8);
}

export function ixDiscriminator(instructionName: string): Buffer {
  return discriminator('global', instructionName);
}

export function accountDiscriminator(accountName: string): Buffer {
  return discriminator('account', accountName);
}

export function encodeI64(value: bigint | number): Buffer {
  const buf = Buffer.alloc(8);
  buf.writeBigInt64LE(BigInt(value));
  return buf;
}

export function encodeU64(value: bigint | number): Buffer {
  const buf = Buffer.alloc(8);
  buf.writeBigUInt64LE(BigInt(value));
  return buf;
}

export function encodeU8(value: number): Buffer {
  return Buffer.from([value]);
}

// ---------------------------------------------------------------
// Instruction argument encoders — field order must match the #[program]
// fn signatures in lib.rs exactly.
// ---------------------------------------------------------------

export function ixInitializeVault(args: {
  withdrawalDelay: bigint; addressDelay: bigint; confirmationWindow: bigint;
  policyDelay: bigint; minWithdrawalDelay: bigint; minAddressDelay: bigint;
}): Buffer {
  return Buffer.concat([
    ixDiscriminator('initialize_vault'),
    encodeI64(args.withdrawalDelay),
    encodeI64(args.addressDelay),
    encodeI64(args.confirmationWindow),
    encodeI64(args.policyDelay),
    encodeI64(args.minWithdrawalDelay),
    encodeI64(args.minAddressDelay),
  ]);
}

export function ixSetParam(instruction: string, newValue: bigint): Buffer {
  return Buffer.concat([ixDiscriminator(instruction), encodeI64(newValue)]);
}

export function ixParamOnly(instruction: string, param: number): Buffer {
  return Buffer.concat([ixDiscriminator(instruction), encodeU8(param)]);
}

export function ixNoArgs(instruction: string): Buffer {
  return ixDiscriminator(instruction);
}

export function ixAmountOnly(instruction: string, amount: bigint): Buffer {
  return Buffer.concat([ixDiscriminator(instruction), encodeU64(amount)]);
}

// ---------------------------------------------------------------
// PDA derivation — seeds/prefixes must match state.rs exactly.
// ---------------------------------------------------------------

export function vaultPda(programId: PublicKey, owner: PublicKey): [PublicKey, number] {
  return PublicKey.findProgramAddressSync(
    [Buffer.from('avelock-vault'), owner.toBuffer()],
    programId,
  );
}

export function extensionPda(programId: PublicKey, vault: PublicKey): [PublicKey, number] {
  return PublicKey.findProgramAddressSync(
    [Buffer.from('avelock-extension'), vault.toBuffer()],
    programId,
  );
}

export function allowlistPda(programId: PublicKey, extension: PublicKey, destination: PublicKey): [PublicKey, number] {
  return PublicKey.findProgramAddressSync(
    [Buffer.from('avelock-allowlist'), extension.toBuffer(), destination.toBuffer()],
    programId,
  );
}

export function requestPda(programId: PublicKey, extension: PublicKey, id: bigint): [PublicKey, number] {
  const idBuf = Buffer.alloc(8);
  idBuf.writeBigUInt64LE(id);
  return PublicKey.findProgramAddressSync(
    [Buffer.from('avelock-request'), extension.toBuffer(), idBuf],
    programId,
  );
}

// ---------------------------------------------------------------
// Account decoders — sequential borsh reads; field order/types must
// match state.rs exactly. `Option<Pubkey>` is a 1-byte tag plus 32 bytes
// only when the tag is 1, so every field's offset after `mint` in
// WithdrawalRequest depends on this at runtime, not a fixed layout.
// ---------------------------------------------------------------

export type SecurityExtensionAccount = {
  wallet: PublicKey;
  withdrawalDelay: bigint;
  addressDelay: bigint;
  confirmationWindow: bigint;
  policyDelay: bigint;
  minWithdrawalDelay: bigint;
  minAddressDelay: bigint;
  nextRequestId: bigint;
  pending: { newValue: bigint; effectiveAt: bigint; exists: boolean }[];
  bump: number;
  guards: { key: PublicKey; activeAt: bigint; removableAt: bigint }[];
  lockDelay: bigint;
  locked: boolean;
  unlockAfter: bigint;
  lockEpoch: bigint;
  lockTimes: bigint[];
};

export const PARAM_COUNT = 5;
export const MAX_GUARDS = 2;
export const LOCK_HISTORY = 4;

export function decodeSecurityExtension(data: Buffer): SecurityExtensionAccount {
  let o = 8; // skip discriminator
  const wallet = new PublicKey(data.subarray(o, o + 32)); o += 32;
  const withdrawalDelay = data.readBigInt64LE(o); o += 8;
  const addressDelay = data.readBigInt64LE(o); o += 8;
  const confirmationWindow = data.readBigInt64LE(o); o += 8;
  const policyDelay = data.readBigInt64LE(o); o += 8;
  const minWithdrawalDelay = data.readBigInt64LE(o); o += 8;
  const minAddressDelay = data.readBigInt64LE(o); o += 8;
  const nextRequestId = data.readBigUInt64LE(o); o += 8;
  const pending = [] as { newValue: bigint; effectiveAt: bigint; exists: boolean }[];
  for (let i = 0; i < PARAM_COUNT; i++) {
    const newValue = data.readBigInt64LE(o); o += 8;
    const effectiveAt = data.readBigInt64LE(o); o += 8;
    const exists = data.readUInt8(o) === 1; o += 1;
    pending.push({ newValue, effectiveAt, exists });
  }
  const bump = data.readUInt8(o); o += 1;
  const guards = [] as { key: PublicKey; activeAt: bigint; removableAt: bigint }[];
  for (let i = 0; i < MAX_GUARDS; i++) {
    const key = new PublicKey(data.subarray(o, o + 32)); o += 32;
    const activeAt = data.readBigInt64LE(o); o += 8;
    const removableAt = data.readBigInt64LE(o); o += 8;
    guards.push({ key, activeAt, removableAt });
  }
  const lockDelay = data.readBigInt64LE(o); o += 8;
  const locked = data.readUInt8(o) === 1; o += 1;
  const unlockAfter = data.readBigInt64LE(o); o += 8;
  const lockEpoch = data.readBigUInt64LE(o); o += 8;
  const lockTimes = [] as bigint[];
  for (let i = 0; i < LOCK_HISTORY; i++) { lockTimes.push(data.readBigInt64LE(o)); o += 8; }
  return { wallet, withdrawalDelay, addressDelay, confirmationWindow, policyDelay, minWithdrawalDelay, minAddressDelay, nextRequestId, pending, bump, guards, lockDelay, locked, unlockAfter, lockEpoch, lockTimes };
}

export type AllowlistEntryAccount = {
  extension: PublicKey;
  destination: PublicKey;
  activeAt: bigint;
  epoch: bigint;
  bump: number;
  lockEpochAtAdd: bigint;
};

export function decodeAllowlistEntry(data: Buffer): AllowlistEntryAccount {
  let o = 8;
  const extension = new PublicKey(data.subarray(o, o + 32)); o += 32;
  const destination = new PublicKey(data.subarray(o, o + 32)); o += 32;
  const activeAt = data.readBigInt64LE(o); o += 8;
  const epoch = data.readBigUInt64LE(o); o += 8;
  const bump = data.readUInt8(o); o += 1;
  const lockEpochAtAdd = data.readBigUInt64LE(o); o += 8;
  return { extension, destination, activeAt, epoch, bump, lockEpochAtAdd };
}

export type WithdrawalRequestAccount = {
  extension: PublicKey;
  id: bigint;
  to: PublicKey;
  mint: PublicKey | null;
  amount: bigint;
  availableAt: bigint;
  expiresAt: bigint;
  epochAtRequest: bigint;
  executed: boolean;
  cancelled: boolean;
  bump: number;
  lockEpochAtRequest: bigint;
};

export function decodeWithdrawalRequest(data: Buffer): WithdrawalRequestAccount {
  let o = 8;
  const extension = new PublicKey(data.subarray(o, o + 32)); o += 32;
  const id = data.readBigUInt64LE(o); o += 8;
  const to = new PublicKey(data.subarray(o, o + 32)); o += 32;
  const hasMint = data.readUInt8(o) === 1; o += 1;
  let mint: PublicKey | null = null;
  if (hasMint) { mint = new PublicKey(data.subarray(o, o + 32)); o += 32; }
  const amount = data.readBigUInt64LE(o); o += 8;
  const availableAt = data.readBigInt64LE(o); o += 8;
  const expiresAt = data.readBigInt64LE(o); o += 8;
  const epochAtRequest = data.readBigUInt64LE(o); o += 8;
  const executed = data.readUInt8(o) === 1; o += 1;
  const cancelled = data.readUInt8(o) === 1; o += 1;
  const bump = data.readUInt8(o); o += 1;
  const lockEpochAtRequest = data.readBigUInt64LE(o); o += 8;
  return { extension, id, to, mint, amount, availableAt, expiresAt, epochAtRequest, executed, cancelled, bump, lockEpochAtRequest };
}

export type VaultAccount = { owner: PublicKey; securityExtension: PublicKey; bump: number };

export function decodeVault(data: Buffer): VaultAccount {
  let o = 8;
  const owner = new PublicKey(data.subarray(o, o + 32)); o += 32;
  const securityExtension = new PublicKey(data.subarray(o, o + 32)); o += 32;
  const bump = data.readUInt8(o); o += 1;
  return { owner, securityExtension, bump };
}

export const PARAM_WITHDRAWAL_DELAY = 0;
export const PARAM_ADDRESS_DELAY = 1;
export const PARAM_CONFIRMATION_WINDOW = 2;
export const PARAM_POLICY_DELAY = 3;
export const PARAM_LOCK_DELAY = 4;
