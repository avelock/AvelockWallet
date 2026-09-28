// Owner-signed operations sent to a signer.
//
// Every operation is bound to one vault account, a strictly increasing
// nonce and an expiry, and is Schnorr-signed by the account's identity key
// (the generation-0 owner key). The signed digest is
//   taggedHash("Avelock/signer-op", canonicalJson(body))
// so a signature can't be replayed, reused for another account or
// confused with a Bitcoin transaction signature.

import * as bitcoin from 'bitcoinjs-lib';
import * as ecc from '@bitcoinerlab/secp256k1';
import type { Signer } from '../spend';

export type Operation =
  | { op: 'register'; accountXpub: string; vault: VaultConfig; policy: Policy; floors: Floors }
  | { op: 'addAddress'; address: string }
  | { op: 'removeAddress'; address: string }
  /** `intent`: see signWithdrawalIntent — lets the owner's devices check the request later. */
  | { op: 'requestWithdrawal'; to: string; amount: number; intent?: string }
  | { op: 'cancelWithdrawal'; requestId: number }
  | { op: 'addGeneration'; vault: VaultConfig }
  | { op: 'changePolicy'; policy: Policy }
  | { op: 'applyPolicyChange' }
  | { op: 'cancelPolicyChange' }
  /** SOS endpoint for duress signals (https, or http on localhost); null disables. */
  | { op: 'setSos'; url: string | null }
  // Guard keys and Panic Lock (FEATURE_PLANS.md, B1/B2).
  | { op: 'addGuard'; guard: string }
  | { op: 'removeGuard'; guard: string }
  | { op: 'cancelGuardRemoval'; guard: string }
  | { op: 'finalizeGuardRemoval'; guard: string }
  | { op: 'lock' }
  | { op: 'unlock' };

/**
 * What a guard key may do: stop things, never move coins, add destinations
 * or guards, change the policy or unlock.
 */
export type GuardOperation =
  | { op: 'guardCancelWithdrawal'; requestId: number }
  | { op: 'guardCancelPolicyChange' }
  | { op: 'guardCancelPendingAddress'; address: string }
  | { op: 'guardDropPendingGuard'; guard: string }
  | { op: 'guardLock' }
  /** The state a guard needs to watch: pending requests, changes and the lock. */
  | { op: 'guardRead' };

/** Signed by the guard key (x-only `guard`), with its own nonce per guard. */
export interface GuardBody {
  domain: SignerDomain;
  account: string;     // the vault account (identity key)
  guard: string;       // guard x-only public key, hex
  nonce: number;       // the guard's next nonce (reads: any)
  expiresAt: number;
  operation: GuardOperation;
}

export interface SignedGuardOperation {
  body: GuardBody;
  signature: string;
}

/** Everything needed to rebuild a vault address (public keys only). */
export interface VaultConfig {
  generation: number; // owner key = accountXpub/0/<generation>
  owner: string;      // x-only hex
  signers: string[];  // x-only hex
  /** Signers that must co-sign with the owner. Always stated (audit A13-7b). */
  threshold: number;
  reserveBlocks: number;
  heir?: string;      // x-only hex
  heirBlocks?: number;
}

/** Permanent minimum delays, fixed at registration; no operation lowers them. */
export interface Floors {
  withdrawalDelay: number;
  addressDelay: number;
}

/** Delays are in seconds; fee cap is in satoshis per withdrawal. */
export interface Policy {
  withdrawalDelay: number;
  addressDelay: number;
  policyDelay: number;
  confirmationWindow: number;
  maxFee: number;
  /** Minimum reserve-door CSV for new generations; defaults to generation 0's. */
  reserveBlocks?: number;
  /** Heir key for new generations; null removes the heir, undefined keeps generation 0's. */
  heir?: string | null;
  /** Minimum heir-door CSV for new generations; defaults to generation 0's. */
  heirBlocks?: number;
  /** Wait before the owner can lift a Panic Lock; default max(7 days, withdrawalDelay). */
  lockDelay?: number;
  /** Signer set for new generations (x-only hex); undefined keeps generation 0's. */
  signers?: string[];
  /** How many of `signers` must co-sign; undefined keeps generation 0's. */
  threshold?: number;
}

/**
 * Binds a signature to one signer on one network, so an operation signed
 * for one service (or for testnet instead of signet) is rejected by any other.
 */
export interface SignerDomain {
  network: NetworkName;
  signer: string;      // signer x-only public key, hex
}

export type NetworkName = 'bitcoin' | 'testnet' | 'signet' | 'regtest' | 'litecoin' | 'litecoin-testnet';

export interface OperationBody {
  domain: SignerDomain;
  account: string;     // identity key, x-only hex
  nonce: number;       // must equal the account's next nonce
  expiresAt: number;   // unix seconds
  duress?: boolean;    // set silently by the app after a Duress PIN unlock
  /** The account state head the client last saw; required after registration (rollback detection). */
  head?: string;
  operation: Operation;
}

/** Owner-signed read request; no nonce, short expiry. */
export interface ReadBody {
  domain: SignerDomain;
  account: string;
  expiresAt: number;
  /**
   * The head seq this device last verified: the reply then carries every
   * state event after it, so the device can check that the signer's current
   * head extends its own and was not rebuilt after a rollback (audit M-8).
   */
  operation: { op: 'read'; since?: number };
}

/** One entry of an account's state hash chain. */
export interface StateEvent {
  seq: number;
  event: unknown;
}

/** Next link of the state hash chain: sha256(previous hash || canonicalJson(event)). */
export function nextStateHash(previousHash: string, event: unknown): string {
  return bitcoin.crypto.sha256(Buffer.concat([
    Buffer.from(previousHash, 'hex'), Buffer.from(canonicalJson(event)),
  ])).toString('hex');
}

export interface SignedOperation {
  body: OperationBody;
  signature: string;   // 64-byte Schnorr, hex
}

const TAG = 'Avelock/signer-op';

/** JSON with object keys sorted recursively, so both sides hash identical bytes. */
export function canonicalJson(value: unknown): string {
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(',')}]`;
  if (value && typeof value === 'object') {
    const entries = Object.entries(value as Record<string, unknown>)
      .filter(([, v]) => v !== undefined)
      .sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0));
    return `{${entries.map(([k, v]) => `${JSON.stringify(k)}:${canonicalJson(v)}`).join(',')}}`;
  }
  return JSON.stringify(value);
}

export function operationDigest(body: OperationBody | ReadBody): Buffer {
  const tag = bitcoin.crypto.sha256(Buffer.from(TAG));
  return bitcoin.crypto.sha256(Buffer.concat([tag, tag, Buffer.from(canonicalJson(body))]));
}

export function signOperation(body: OperationBody, identity: Signer): SignedOperation {
  const full = withIntent(body, identity);
  return { body: full, signature: identity.signSchnorr(operationDigest(full)).toString('hex') };
}

export interface SignedRead {
  body: ReadBody;
  signature: string;
}

export function signRead(body: ReadBody, identity: Signer): SignedRead {
  return { body, signature: identity.signSchnorr(operationDigest(body)).toString('hex') };
}

/**
 * What the owner signed for one withdrawal request: recipient and amount,
 * bound to the signer, the account and the operation's nonce (so one
 * signature makes one request). The signer keeps it with the request and
 * returns it on every read: the account state it reports is not otherwise
 * tied to the owner's signatures, and without this a compromised signer
 * could show a made-up request that the owner's app would then co-sign.
 * No duress flag in it (audit M-7): it is readable with the phrase.
 */
export interface WithdrawalIntent {
  domain: SignerDomain;
  account: string;
  nonce: number;
  to: string;
  amount: number;
}

const INTENT_TAG = 'Avelock/withdrawal-intent';

export function intentDigest(intent: WithdrawalIntent): Buffer {
  const tag = bitcoin.crypto.sha256(Buffer.from(INTENT_TAG));
  return bitcoin.crypto.sha256(Buffer.concat([tag, tag, Buffer.from(canonicalJson(intent))]));
}

export function signWithdrawalIntent(intent: WithdrawalIntent, identity: Signer): string {
  return identity.signSchnorr(intentDigest(intent)).toString('hex');
}

export function verifyWithdrawalIntent(intent: WithdrawalIntent, signature: string): boolean {
  try {
    return ecc.verifySchnorr(intentDigest(intent), Buffer.from(intent.account, 'hex'), Buffer.from(signature, 'hex'));
  } catch {
    return false;
  }
}

/** A requestWithdrawal body with its intent signature filled in (other bodies unchanged). */
export function withIntent(body: OperationBody, identity: Signer): OperationBody {
  const op = body.operation;
  if (op.op !== 'requestWithdrawal' || op.intent) return body;
  const intent = signWithdrawalIntent({ domain: body.domain, account: body.account, nonce: body.nonce, to: op.to, amount: op.amount }, identity);
  return { ...body, operation: { ...op, intent } };
}

const GUARD_TAG = 'Avelock/signer-guard-op';

/** A separate tag: a guard signature can never pass as an owner operation. */
export function guardDigest(body: GuardBody): Buffer {
  const tag = bitcoin.crypto.sha256(Buffer.from(GUARD_TAG));
  return bitcoin.crypto.sha256(Buffer.concat([tag, tag, Buffer.from(canonicalJson(body))]));
}

export function signGuardOperation(body: GuardBody, guard: Signer): SignedGuardOperation {
  return { body, signature: guard.signSchnorr(guardDigest(body)).toString('hex') };
}

export function verifyGuardOperation(signed: SignedGuardOperation): boolean {
  try {
    return ecc.verifySchnorr(guardDigest(signed.body), Buffer.from(signed.body.guard, 'hex'), Buffer.from(signed.signature, 'hex'));
  } catch {
    return false;
  }
}

export function verifyOperation(signed: SignedOperation | SignedRead): boolean {
  try {
    return ecc.verifySchnorr(
      operationDigest(signed.body),
      Buffer.from(signed.body.account, 'hex'),
      Buffer.from(signed.signature, 'hex'),
    );
  } catch {
    return false;
  }
}
