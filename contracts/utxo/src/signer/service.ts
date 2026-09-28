// The signer's policy engine.
//
// The signer holds its own key (never derived from any owner seed) and
// adds the second signature of the cosigned door only when the Avelock
// rules hold — the same state machine the EVM/TON contracts enforce:
//
//   address:    add -> wait addressDelay -> active; removal is immediate
//   withdrawal: request -> wait withdrawalDelay -> owner-signed PSBT within
//               confirmationWindow -> signer co-signs once
//   refresh:    move coins into another generation of the same vault;
//               co-signed immediately, but only into generations at least
//               as strong as the current policy
//   policy:     stronger changes apply immediately, weaker ones wait the
//               current policyDelay
//
// Nobody — the owner, an attacker holding the owner's seed, or the operator
// of this service — has an operation that skips a delay.

import * as bitcoin from 'bitcoinjs-lib';
import * as ecc from '@bitcoinerlab/secp256k1';
import { createVault } from '../vault';
import { ownerPublicKey, ownerPublicKeys } from '../keys';
import type { Signer } from '../spend';
import { lookup, LookupAddress } from 'dns';
import { request as httpsRequest } from 'https';
import { isIP } from 'net';
import { Floors, guardDigest, NetworkName, nextStateHash, Operation, OperationBody, Policy, SignedGuardOperation, SignedOperation, SignedRead, SignerDomain, StateEvent, VaultConfig, verifyGuardOperation, verifyOperation, verifyWithdrawalIntent, operationDigest } from './messages';

export const MAX_DELAY = 90 * 86400;
export const MAX_CONFIRMATION_WINDOW = 30 * 86400;
export const MAX_OPERATION_TTL = 3600;
export const DUST = 546;
/** Minimum spacing between co-signed refreshes, so a stolen seed can't burn the vault in fees. */
export const REFRESH_INTERVAL = 86400;
/**
 * While locked: refreshes keep the reserve door shut (a lock must not let it
 * open), but one every 30 days is enough for that — reserve periods are
 * months — and a phrase thief can't burn fees daily behind a lock (audit NEW-M6).
 */
export const REFRESH_INTERVAL_LOCKED = 30 * 86400;

/**
 * The locked spacing for this account: never more than a quarter of its
 * shortest reserve period (audit A11-9), so a vault with a short reserve
 * door is still renewed in time under a lock (no daily floor, A13-4).
 */
export function lockedInterval(a: Pick<Account, 'generations'>, blockSeconds: number): number {
  const reserves = a.generations.map(g => g.reserveBlocks * blockSeconds);
  if (!reserves.length) return REFRESH_INTERVAL_LOCKED;
  // No one-day floor under a lock (A13-4): with a very short reserve door the
  // renewals must come faster than the door opens, whatever that costs.
  return Math.max(1, Math.min(REFRESH_INTERVAL_LOCKED, Math.floor(Math.min(...reserves) / 4)));
}
export const MAX_GENERATIONS = 1000;
/** Upcoming renewals whose owner keys an heir may not equal. */
export const HEIR_KEY_LOOKAHEAD = 100;
export const MAX_PENDING_REQUESTS = 16;
/** New withdrawal requests per account per day: with cancels, the pending cap alone bounds nothing (audit M-11). */
export const MAX_REQUESTS_PER_DAY = 48;
/** Finished requests are dropped this long after their confirmation window ends. */
export const REQUEST_RETENTION = 30 * 86400;
/**
 * State events kept per account for rollback checks (audit M-8). A device
 * that falls further behind than this can't verify the chain and has to
 * trust the signer's state again explicitly. The whole state file is
 * rewritten on every change, so this is kept small.
 */
export const STATE_LOG_SIZE = 256;
/** New accounts per hour for the whole signer, so a registration flood can't fill it unnoticed (audit M-11). */
export const DEFAULT_REGISTRATIONS_PER_HOUR = 60;
export const DEFAULT_MAX_ACCOUNTS = 10_000;
export const MAX_READ_TTL = 300;
/** At most one SOS signal per account in this window. */
export const SOS_INTERVAL = 600;
export const MAX_GUARDS = 2;
/** Default wait before a Panic Lock can be lifted (at least the withdrawal delay). */
export const DEFAULT_LOCK_DELAY = 7 * 86400;

export function lockDelayOf(p: Policy): number {
  // Never shorter than the current withdrawal delay (audit A12-3): after W
  // is raised, an old short lockDelay rises with it, so a thief holding the
  // phrase cannot lift a lock sooner than a withdrawal could complete.
  return Math.max(p.lockDelay ?? DEFAULT_LOCK_DELAY, p.withdrawalDelay);
}

export class SignerError extends Error {
  constructor(public code: string, message: string) {
    super(message);
  }
}

interface Generation extends VaultConfig {
  address: string;
  output: string; // scriptPubKey hex
}

interface AllowedAddress {
  activeAt: number;
  epoch: number;
  /** The account's lock epoch when added (a lock while it waits voids it). */
  lockEpoch?: number;
}

/** A stop-only second key (FEATURE_PLANS.md, B1). */
export interface GuardKey {
  activeAt: number;
  removableAt?: number;
  nonce: number;
}

export type RequestStatus = 'pending' | 'cancelled' | 'signed';

export interface WithdrawalRequest {
  id: number;
  to: string;
  amount: number;
  createdAt: number;
  availableAt: number;
  expiresAt: number;
  addressEpoch: number;
  status: RequestStatus;
  /** Outpoints of the co-signed transaction; a fee bump must spend exactly these. */
  signedInputs?: string[];
  /** The account's lock epoch when made; a later lock voids it. */
  lockEpoch?: number;
  /** The owner's signature over recipient and amount (see WithdrawalIntent). */
  auth: { nonce: number; signature: string };
}

/**
 * Hash chain over every change to an account. Clients remember the latest
 * head and send it with each operation; a signer restored from an old
 * backup has an older head and refuses, which reveals the rollback.
 */
export interface StateHead {
  seq: number;
  hash: string;
}

export interface Account {
  identity: string;
  head: StateHead;
  /** The last STATE_LOG_SIZE events of the hash chain. */
  log?: StateEvent[];
  /** Id of requests[0]: finished requests are pruned from the front. */
  requestBase?: number;
  accountXpub: string;
  floors: Floors;
  lastRefreshAt?: number;
  lastGenerationAt?: number;
  sosUrl?: string;
  /** A change or removal of sosUrl waiting policyWait (audit A15-4). */
  pendingSos?: { url: string | null; effectiveAt: number };
  /** Last "SOS address change asked" notice (A16-4); private like lastSosAt. */
  lastSosChangeAt?: number;
  lastSosAt?: number;
  nonce: number;
  policy: Policy;
  pendingPolicy?: { policy: Policy; effectiveAt: number };
  generations: Generation[];
  allowlist: Record<string, AllowedAddress>;
  addressEpochs: Record<string, number>;
  requests: WithdrawalRequest[];
  /** Guard keys by x-only public key (hex), at most MAX_GUARDS. */
  guards?: Record<string, GuardKey>;
  locked?: boolean;
  unlockAfter?: number;
  lockEpoch?: number;
  /** When each lock epoch began. */
  lockTimes?: Record<number, number>;
}

export interface SignerState {
  accounts: Record<string, Account>;
}

export interface SignerOptions {
  key: Signer;
  network: bitcoin.Network;
  /** Distinguishes networks that share address formats (signet vs testnet). */
  networkName: NetworkName;
  now?: () => number;
  state?: SignerState;
  /** Called after every state change; persist the state here. */
  onChange?: (state: SignerState) => void;
  /** Upper bound on registered accounts (storage abuse). */
  maxAccounts?: number;
  /** Upper bound on new accounts per hour (default DEFAULT_REGISTRATIONS_PER_HOUR). */
  registrationsPerHour?: number;
  /** Development only: accept http://localhost SOS URLs. */
  allowLocalSos?: boolean;
  /** Called (never awaited) when an operation carries the duress flag. */
  onDuress?: (account: string) => void;
  /** Delivers an SOS signal; must not block or throw. Defaults to a background HTTPS POST. */
  sendSos?: (url: string, payload: SosPayload) => void;
}

export interface SosPayload {
  /** 'avelock-sos-change': someone asked to change this SOS address (A16-1). */
  event: 'avelock-duress' | 'avelock-sos-change';
  account: string;
  at: number;
}

const PRIVATE_V4 = [
  [0x00000000, 8], [0x0a000000, 8], [0x64400000, 10], [0x7f000000, 8], [0xa9fe0000, 16],
  [0xac100000, 12], [0xc0000000, 24], [0xc0a80000, 16], [0xc6120000, 15], [0xe0000000, 3],
] as const;

/** Loopback, private, link-local, CGNAT, multicast and reserved addresses. */
export function isPrivateAddress(ip: string): boolean {
  if (isIP(ip) === 4) {
    const n = ip.split('.').reduce((acc, x) => acc * 256 + Number(x), 0);
    return PRIVATE_V4.some(([base, bits]) => Math.floor(n / 2 ** (32 - bits)) === Math.floor(base / 2 ** (32 - bits)));
  }
  const g = ipv6Groups(ip);
  if (!g) return true; // not an address we can read: refuse
  // IPv6 forms that carry an IPv4 address inside (audit A15-6): mapped
  // (::ffff:a.b.c.d, also written ::ffff:7f00:1), compatible (::a.b.c.d),
  // SIIT (::ffff:0:a.b.c.d), NAT64 (64:ff9b::/96, 64:ff9b:1::/48), 6to4 (2002::/16).
  const v4 = (hi: number, lo: number) => `${hi >> 8}.${hi & 255}.${lo >> 8}.${lo & 255}`;
  const zero = (from: number, to: number) => g.slice(from, to).every(x => x === 0);
  if (zero(0, 5) && g[5] === 0xffff) return isPrivateAddress(v4(g[6], g[7]));
  if (zero(0, 4) && g[4] === 0xffff && g[5] === 0) return isPrivateAddress(v4(g[6], g[7]));
  if (zero(0, 6)) return zero(6, 7) && g[7] <= 1 ? true : isPrivateAddress(v4(g[6], g[7]));
  if (g[0] === 0x64 && g[1] === 0xff9b && (zero(2, 6) || g[2] === 1)) return isPrivateAddress(v4(g[6], g[7]));
  if (g[0] === 0x2002) return isPrivateAddress(v4(g[1], g[2]));
  const first = g[0];
  return (first & 0xfe00) === 0xfc00 || (first & 0xffc0) === 0xfe80 || (first & 0xff00) === 0xff00 ||
    (first === 0x2001 && g[1] === 0x0db8) || (first === 0x0100 && zero(1, 4));
}

/** The eight 16-bit groups of an IPv6 address (a trailing dotted IPv4 allowed), or null. */
function ipv6Groups(ip: string): number[] | null {
  let v6 = ip.toLowerCase().replace(/%.*$/, '');
  const dotted = v6.match(/^(.*:)(\d+)\.(\d+)\.(\d+)\.(\d+)$/);
  if (dotted) {
    const b = dotted.slice(2).map(Number);
    if (b.some(x => x > 255)) return null;
    v6 = `${dotted[1]}${((b[0] << 8) | b[1]).toString(16)}:${((b[2] << 8) | b[3]).toString(16)}`;
  }
  const parts = v6.split('::');
  if (parts.length > 2) return null;
  const side = (x: string) => (x ? x.split(':') : []);
  const left = side(parts[0]), right = parts.length === 2 ? side(parts[1]) : [];
  const fill = parts.length === 2 ? 8 - left.length - right.length : 0;
  if (fill < 0 || (parts.length === 1 && left.length !== 8)) return null;
  const all = [...left, ...Array(fill).fill('0'), ...right];
  if (all.length !== 8 || all.some(x => !/^[0-9a-f]{1,4}$/.test(x))) return null;
  return all.map(x => parseInt(x, 16));
}

/**
 * The SOS URL is chosen by whoever holds the phrase, so the signer must not
 * become a way to reach its own network (audit M-11): the address is checked
 * when set and again at every connection (the resolved IP, so DNS rebinding
 * does not help), and redirects are not followed.
 */
export function validateSosUrl(url: string, allowLocal = false) {
  let u: URL;
  try { u = new URL(url); } catch { throw new SignerError('bad_sos', 'invalid SOS URL'); }
  const host = u.hostname.replace(/^\[|\]$/g, '').toLowerCase();
  const local = host === '127.0.0.1' || host === 'localhost';
  if (u.protocol === 'http:' && local && allowLocal) return;
  if (u.protocol !== 'https:') throw new SignerError('bad_sos', 'SOS URL must use https');
  if (u.username || u.password || host === 'localhost' || host.endsWith('.localhost') || host.endsWith('.local') ||
      host.endsWith('.internal') || (isIP(host) && isPrivateAddress(host))) {
    throw new SignerError('bad_sos', 'SOS URL must be a public host');
  }
}

/**
 * DNS lookup for SOS connections that refuses private addresses. Node calls
 * it with `all: true` (happy eyeballs, Node 20+) and then expects an array,
 * or without it and expects one address: answer in the form asked for. Any
 * private address among the answers refuses the host.
 */
export function publicLookup(hostname: string, options: { all?: boolean } & object, callback: (...args: any[]) => void) {
  lookup(hostname, { ...options, all: true }, (err, addresses) => {
    if (err) return callback(err);
    const list = addresses as LookupAddress[];
    if (list.length === 0 || list.some(a => isPrivateAddress(a.address))) {
      return callback(Object.assign(new Error('SOS host resolves to a private address'), { code: 'EPRIVATE' }));
    }
    if (options.all) callback(null, list);
    else callback(null, list[0].address, list[0].family);
  });
}

function postOnce(url: string, body: string): Promise<boolean> {
  const u = new URL(url);
  if (u.protocol === 'http:') {
    // Only reachable for a URL validated with allowLocal (development).
    return fetch(url, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body }).then(r => r.ok);
  }
  return new Promise(resolve => {
    const req = httpsRequest(u, {
      method: 'POST', headers: { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(body) },
      lookup: publicLookup as any, timeout: 10_000,
    }, res => { res.resume(); resolve((res.statusCode ?? 0) >= 200 && (res.statusCode ?? 0) < 300); });
    req.on('timeout', () => req.destroy());
    req.on('error', () => resolve(false));
    req.end(body);
  });
}

/** Background POST with retries; never awaited, never throws. */
export function postSos(url: string, payload: SosPayload, attempts = 5) {
  const body = JSON.stringify(payload);
  void (async () => {
    for (let i = 0; i < attempts; i++) {
      try {
        if (await postOnce(url, body)) return;
      } catch { /* retry */ }
      await new Promise(r => setTimeout(r, 1000 * 2 ** i));
    }
  })();
}

export class SignerService {
  readonly publicKey: string;
  private state: SignerState;
  private now: () => number;
  /** Registration times in the last hour (memory only). */
  private registrations: number[] = [];

  /** A13-4: main networks only; test networks keep short doors for testing. */
  private get minReserveBlocks(): number {
    const main = this.options.networkName === 'bitcoin' || this.options.networkName === 'litecoin';
    return main ? Math.ceil(MIN_RESERVE_SECONDS_MAINNET / this.blockSeconds) : 1;
  }

  /** Litecoin blocks come every 2.5 minutes, Bitcoin's every 10. */
  private get blockSeconds(): number {
    return /ltc/.test(this.options.network.bech32) ? 150 : 600;
  }

  constructor(private options: SignerOptions) {
    this.publicKey = options.key.publicKey.toString('hex');
    this.state = normalizeState(options.state ?? { accounts: {} });
    this.now = options.now ?? (() => Math.floor(Date.now() / 1000));
  }

  get domain(): SignerDomain {
    return { network: this.options.networkName, signer: this.publicKey };
  }

  private requireDomain(domain: SignerDomain | undefined) {
    if (!domain || domain.network !== this.options.networkName || domain.signer !== this.publicKey) {
      throw new SignerError('wrong_domain', 'operation was signed for a different signer or network');
    }
  }

  getAccount(identity: string): Account | undefined {
    return this.state.accounts[identity];
  }

  /**
   * Owner-authenticated account read (the state is private to the owner).
   * With `since`, the reply carries the state events after that seq.
   */
  readAccount(signed: SignedRead): Account & { events?: StateEvent[] } {
    const now = this.now();
    if (signed.body?.operation?.op !== 'read' || !verifyOperation(signed)) throw new SignerError('bad_signature', 'invalid read signature');
    this.requireDomain(signed.body.domain);
    if (!(signed.body.expiresAt >= now && signed.body.expiresAt <= now + MAX_READ_TTL)) throw new SignerError('expired', 'read request expired');
    // lastSosAt stays private too: whoever holds the phrase can read the
    // account, and a fresh SOS time would reveal the Duress PIN (audit M-7).
    // The SOS address stays private as well: whoever holds the phrase must not
    // learn whether an alarm is set up, or where it goes (audit A15-4).
    const { lastSosAt: _hidden, lastSosChangeAt: _notice, sosUrl: _sos, pendingSos: _pendingSos, log, ...visible } = this.requireAccount(signed.body.account);
    const since = signed.body.operation.since;
    if (since === undefined) return visible as Account;
    if (!Number.isSafeInteger(since) || since < 0) throw new SignerError('bad_request', 'invalid since');
    return { ...visible, events: (log ?? []).filter(e => e.seq > since) } as Account & { events: StateEvent[] };
  }

  /** State events after `seq` (for replies to co-signing requests). */
  eventsAfter(identity: string, seq: number): StateEvent[] {
    return (this.requireAccount(identity).log ?? []).filter(e => e.seq > seq);
  }

  private advance(a: Account, event: unknown) {
    a.head = { seq: a.head.seq + 1, hash: nextStateHash(a.head.hash, event) };
    a.log = [...(a.log ?? []), { seq: a.head.seq, event }].slice(-STATE_LOG_SIZE);
  }

  private requireHead(a: Account, head: string | undefined) {
    if (head !== a.head.hash) {
      throw new SignerError('stale_state', `state head mismatch (signer is at #${a.head.seq}); refresh, or report a possible rollback`);
    }
  }

  // ---------------------------------------------------------------
  // Owner operations
  // ---------------------------------------------------------------

  submit(signed: SignedOperation): unknown {
    const { body } = signed;
    const now = this.now();
    if (!verifyOperation(signed)) throw new SignerError('bad_signature', 'invalid operation signature');
    this.requireDomain(body.domain);
    if (!(body.expiresAt >= now && body.expiresAt <= now + MAX_OPERATION_TTL)) {
      throw new SignerError('expired', 'operation expired or expiry too far ahead');
    }
    const account = this.state.accounts[body.account];
    if (body.operation.op === 'register') {
      if (account) throw new SignerError('exists', 'account already registered');
      if (body.nonce !== 0) throw new SignerError('bad_nonce', 'registration nonce must be 0');
    } else {
      if (!account) throw new SignerError('unknown_account', 'account is not registered');
      if (body.nonce !== account.nonce) throw new SignerError('bad_nonce', `expected nonce ${account.nonce}`);
      this.requireHead(account, body.head);
    }
    if (body.duress) this.reportDuress(body.account);

    const before = this.snapshot(body.account);
    let result: Record<string, unknown>;
    this.afterCommit = undefined;
    try {
      result = this.apply(body, account, now) as Record<string, unknown>;
    } catch (e) {
      this.afterCommit = undefined;
      // apply() validates before it mutates, but restore anyway on any throw.
      if (before === undefined) delete this.state.accounts[body.account];
      else this.state.accounts[body.account] = normalizeAccount(JSON.parse(before));
      throw e;
    }
    const a = this.state.accounts[body.account];
    a.nonce = body.nonce + 1;
    this.advance(a, { op: operationDigest(body).toString('hex') });
    this.commit(body.account, before);
    const notice = this.afterCommit as (() => void) | undefined; // set inside apply()
    this.afterCommit = undefined;
    if (notice) try { notice(); } catch { /* never blocks */ }
    return { ...result, head: a.head };
  }

  /** A notice to send once the operation's state is saved (A16-4). */
  private afterCommit?: () => void;

  private apply(body: OperationBody, account: Account | undefined, now: number): unknown {
    const op: Operation = body.operation;
    switch (op.op) {
      case 'register': {
        validatePolicy(op.policy);
        if (Object.keys(this.state.accounts).length >= (this.options.maxAccounts ?? DEFAULT_MAX_ACCOUNTS)) {
          throw new SignerError('full', 'this signer does not accept new accounts');
        }
        this.registrations = this.registrations.filter(t => t > now - 3600);
        if (this.registrations.length >= (this.options.registrationsPerHour ?? DEFAULT_REGISTRATIONS_PER_HOUR)) {
          throw new SignerError('rate_limited', 'too many new accounts right now; try again later');
        }
        validateFloors(op.floors, op.policy);
        if (op.vault.generation !== 0 || op.vault.owner !== body.account) {
          throw new SignerError('bad_vault', 'generation 0 owner key must be the account identity key');
        }
        validateTerms(effectiveTerms(op.policy, op.vault), this.publicKey, this.minReserveBlocks);
        const created: Account = {
          identity: body.account, head: { seq: 0, hash: '00'.repeat(32) }, accountXpub: op.accountXpub, floors: { ...op.floors }, nonce: 0, policy: op.policy, generations: [],
          allowlist: dict(), addressEpochs: dict(), requests: [],
        };
        created.generations.push(this.generation(op.vault, created));
        this.state.accounts[body.account] = created;
        this.registrations.push(now);
        return { address: created.generations[0].address };
      }
      case 'addGeneration': {
        const a = account!;
        if (a.generations.some(g => g.generation === op.vault.generation)) throw new SignerError('bad_vault', 'generation already registered');
        if (a.generations.length >= MAX_GENERATIONS) throw new SignerError('full', 'too many vault generations');
        // One new generation a day, like refreshes: otherwise a thief with the
        // phrase fills the generation limit in seconds and renewals stop.
        // Under a Panic Lock — the owner's answer to a stolen phrase — one in
        // 30 days, like locked refreshes: filling the limit then takes ~82
        // years instead of ~2.7 (audit R-19 / AVL-BTC-003).
        const g = this.generation(op.vault, a);
        const interval = a.locked ? lockedInterval(a, this.blockSeconds) : REFRESH_INTERVAL;
        if (a.lastGenerationAt !== undefined && now < a.lastGenerationAt + interval) {
          throw new SignerError('rate_limited', a.locked ? `while locked, one new vault generation per ${Math.round(interval / 86400)} days` : 'one new vault generation per day');
        }
        a.generations.push(g);
        a.lastGenerationAt = now;
        return { address: g.address };
      }
      case 'addAddress': {
        const a = account!;
        requireUnlocked(a);
        this.parseAddress(op.address);
        const existing = a.allowlist[op.address];
        if (existing && voidedByLock(a, existing)) {
          // Voided by a lock while it waited: it is added again and waits again.
          delete a.allowlist[op.address];
          a.addressEpochs[op.address] = (a.addressEpochs[op.address] ?? 0) + 1;
        }
        if (!a.allowlist[op.address]) {
          // Re-adding never resets or shortens an existing activation.
          a.allowlist[op.address] = { activeAt: now + a.policy.addressDelay, epoch: a.addressEpochs[op.address] ?? 0, lockEpoch: a.lockEpoch ?? 0 };
        }
        return { activeAt: a.allowlist[op.address].activeAt };
      }
      case 'removeAddress': {
        const a = account!;
        if (a.allowlist[op.address]) {
          delete a.allowlist[op.address];
          // Bumping the epoch invalidates every request made to this address.
          a.addressEpochs[op.address] = (a.addressEpochs[op.address] ?? 0) + 1;
        }
        return {};
      }
      case 'requestWithdrawal': {
        const a = account!;
        requireUnlocked(a);
        const allowed = a.allowlist[op.to];
        if (!allowed || allowed.activeAt > now || voidedByLock(a, allowed)) throw new SignerError('address_not_active', 'destination is not an active allowlisted address');
        if (!Number.isSafeInteger(op.amount) || op.amount < DUST) throw new SignerError('bad_amount', 'amount below dust or invalid');
        const intent = { domain: body.domain, account: body.account, nonce: body.nonce, to: op.to, amount: op.amount };
        if (typeof op.intent !== 'string' || !verifyWithdrawalIntent(intent, op.intent)) {
          throw new SignerError('bad_signature', 'withdrawal intent missing or invalid');
        }
        if (a.requests.filter(r => r.status === 'pending' && r.expiresAt >= now).length >= MAX_PENDING_REQUESTS) {
          throw new SignerError('full', 'too many pending requests; cancel some first');
        }
        if (a.requests.filter(r => r.createdAt > now - 86400).length >= MAX_REQUESTS_PER_DAY) {
          throw new SignerError('rate_limited', 'too many withdrawal requests today');
        }
        // Drop long-finished requests from the front; ids stay stable.
        while (a.requests.length && a.requests[0].expiresAt + REQUEST_RETENTION < now) {
          a.requests.shift();
          a.requestBase = (a.requestBase ?? 0) + 1;
        }
        const availableAt = now + a.policy.withdrawalDelay;
        const request: WithdrawalRequest = {
          id: (a.requestBase ?? 0) + a.requests.length, to: op.to, amount: op.amount, createdAt: now,
          availableAt, expiresAt: availableAt + a.policy.confirmationWindow,
          // No duress mark here (audit M-7): the account is readable with
          // the same phrase, so a stored flag would tell the coercer.
          addressEpoch: allowed.epoch, status: 'pending', lockEpoch: a.lockEpoch ?? 0,
          auth: { nonce: body.nonce, signature: op.intent },
        };
        a.requests.push(request);
        return request;
      }
      case 'cancelWithdrawal': {
        const r = requestById(account!, op.requestId);
        if (!r || r.status !== 'pending') throw new SignerError('bad_request', 'no pending request with this id');
        r.status = 'cancelled';
        return r;
      }
      case 'changePolicy': {
        const a = account!;
        requireUnlocked(a);
        validatePolicy(op.policy);
        validateFloors(a.floors, op.policy);
        validateReserveFloor(a, op.policy);
        validateTerms(effectiveTerms(op.policy, a.generations[0]), this.publicKey, this.minReserveBlocks);
        this.validateBuildable(a, op.policy);
        // Every change waits the policy delay — including "stronger" ones.
        // An instant tightening lets a thief with the phrase lock the owner
        // out (90-day delays, zero fee cap, longer reserve) for leverage.
        a.pendingPolicy = { policy: op.policy, effectiveAt: now + policyWait(a) };
        return { applied: false, effectiveAt: a.pendingPolicy.effectiveAt };
      }
      case 'applyPolicyChange': {
        const a = account!;
        requireUnlocked(a);
        if (!a.pendingPolicy) throw new SignerError('no_pending', 'no pending policy change');
        if (a.pendingPolicy.effectiveAt > now) throw new SignerError('too_early', 'policy delay has not elapsed');
        a.policy = a.pendingPolicy.policy;
        a.pendingPolicy = undefined;
        return { applied: true };
      }
      case 'cancelPolicyChange': {
        account!.pendingPolicy = undefined;
        return {};
      }
      case 'setSos': {
        // Every change waits like a policy change, the first setting too: a
        // thief with the phrase could otherwise quietly point the alarm at
        // himself and learn when the Duress PIN is used (audit A15-4, A16-1).
        // A lock drops it. The current address is told a change was asked
        // for. Nothing about SOS is ever returned to a reader.
        const a = account!;
        requireUnlocked(a);
        if (op.url !== null) validateSosUrl(op.url, this.options.allowLocalSos);
        settleSos(a, now);
        if ((op.url ?? undefined) === a.sosUrl) {
          a.pendingSos = undefined;
        } else {
          a.pendingSos = { url: op.url, effectiveAt: now + policyWait(a) };
          // At most one notice per SOS_INTERVAL, so a thief cannot flood the
          // recipient into ignoring them; sent only once the state is saved (A16-4).
          if (a.sosUrl && (a.lastSosChangeAt === undefined || now >= a.lastSosChangeAt + SOS_INTERVAL)) {
            a.lastSosChangeAt = now;
            const url = a.sosUrl;
            this.afterCommit = () => (this.options.sendSos ?? postSos)(url, { event: 'avelock-sos-change', account: body.account, at: now });
          }
        }
        return {};
      }
      // Guard keys: adding and removing both wait addressDelay, so a stolen
      // phrase can't quietly swap them; a guard can't stop its own removal.
      case 'addGuard': {
        const a = account!;
        requireUnlocked(a);
        requireXOnly(op.guard);
        if (op.guard === a.identity) throw new SignerError('bad_guard', 'the owner key cannot be a guard');
        const guards = (a.guards ??= dict());
        if (guards[op.guard]) throw new SignerError('bad_guard', 'this guard is already added');
        if (Object.keys(guards).length >= MAX_GUARDS) throw new SignerError('full', `at most ${MAX_GUARDS} guard keys`);
        guards[op.guard] = { activeAt: now + a.policy.addressDelay, nonce: 0 };
        return { activeAt: guards[op.guard].activeAt };
      }
      case 'removeGuard': {
        const a = account!;
        const g = requireGuard(a, op.guard);
        if (now < g.activeAt) {
          delete a.guards![op.guard];
          return { removed: true };
        }
        // Queued only while unlocked; a lock drops it (audit A15-1).
        if (g.removableAt === undefined) {
          requireUnlocked(a);
          g.removableAt = now + a.policy.addressDelay;
        }
        return { removableAt: g.removableAt };
      }
      case 'cancelGuardRemoval': {
        const g = requireGuard(account!, op.guard);
        if (g.removableAt === undefined) throw new SignerError('no_pending', 'no removal is queued');
        g.removableAt = undefined;
        return {};
      }
      case 'finalizeGuardRemoval': {
        const a = account!;
        const g = requireGuard(a, op.guard);
        if (g.removableAt === undefined) throw new SignerError('no_pending', 'no removal is queued');
        if (now < g.removableAt) throw new SignerError('too_early', 'the removal delay has not elapsed');
        // Never during a lock (audit A15-1): else a phrase thief waits out
        // the guard's lock and no one is left to extend it.
        requireUnlocked(a);
        delete a.guards![op.guard];
        return { removed: true };
      }
      case 'lock':
        lock(account!, now);
        return { unlockAfter: account!.unlockAfter };
      case 'unlock': {
        const a = account!;
        if (!a.locked) throw new SignerError('not_locked', 'the vault is not locked');
        if (now < a.unlockAfter!) throw new SignerError('too_early', 'the lock cannot be lifted yet');
        a.locked = false;
        return {};
      }
    }
  }

  // ---------------------------------------------------------------
  // Guard operations: signed by an active guard key, stop-only.
  // ---------------------------------------------------------------

  guardSubmit(signed: SignedGuardOperation): unknown {
    const { body } = signed;
    const now = this.now();
    if (!verifyGuardOperation(signed)) throw new SignerError('bad_signature', 'invalid guard signature');
    this.requireDomain(body.domain);
    if (!(body.expiresAt >= now && body.expiresAt <= now + MAX_OPERATION_TTL)) throw new SignerError('expired', 'operation expired or expiry too far ahead');
    const a = this.requireAccount(body.account);
    const before = this.snapshot(body.account);
    const g = a.guards && typeof body.guard === 'string' && Object.hasOwn(a.guards, body.guard) ? a.guards[body.guard] : undefined;
    if (!g || now < g.activeAt) throw new SignerError('not_guard', 'not an active guard of this vault');
    const op = body.operation;
    if (op.op === 'guardRead') {
      // A guard watches what it may stop; nothing else of the account.
      return {
        locked: !!a.locked, unlockAfter: a.unlockAfter, lockDelay: lockDelayOf(a.policy), guardNonce: g.nonce,
        pendingPolicyAt: a.pendingPolicy?.effectiveAt,
        requests: a.requests.filter(r => r.status === 'pending' && r.expiresAt >= now && !isAnnulled(a, r)),
        pendingAddresses: Object.entries(a.allowlist).filter(([, e]) => e.activeAt > now).map(([address, e]) => ({ address, activeAt: e.activeAt })),
        pendingGuards: Object.entries(a.guards ?? {}).filter(([, x]) => x.activeAt > now).map(([guard, x]) => ({ guard, activeAt: x.activeAt })),
      };
    }
    if (body.nonce !== g.nonce) throw new SignerError('bad_nonce', `expected nonce ${g.nonce}`);
    switch (op.op) {
      case 'guardCancelWithdrawal': {
        const r = requestById(a, op.requestId);
        if (!r || r.status !== 'pending') throw new SignerError('bad_request', 'no pending request with this id');
        r.status = 'cancelled';
        break;
      }
      case 'guardCancelPolicyChange':
        if (!a.pendingPolicy) throw new SignerError('no_pending', 'no pending policy change');
        a.pendingPolicy = undefined;
        break;
      case 'guardCancelPendingAddress': {
        const e = a.allowlist[op.address];
        if (!e || e.activeAt <= now) throw new SignerError('no_pending', 'this address is not waiting');
        delete a.allowlist[op.address];
        a.addressEpochs[op.address] = (a.addressEpochs[op.address] ?? 0) + 1;
        break;
      }
      case 'guardDropPendingGuard': {
        requireXOnly(op.guard);
        const other = a.guards && Object.hasOwn(a.guards, op.guard) ? a.guards[op.guard] : undefined;
        if (!other || other.activeAt <= now) throw new SignerError('no_pending', 'this guard is not waiting');
        delete a.guards![op.guard];
        break;
      }
      case 'guardLock':
        lock(a, now);
        break;
      default:
        throw new SignerError('bad_request', 'unknown guard operation');
    }
    g.nonce += 1;
    this.advance(a, { guard: body.guard, op: guardDigest(body).toString('hex') });
    this.commit(body.account, before);
    return { head: a.head, locked: !!a.locked, unlockAfter: a.unlockAfter };
  }

  // ---------------------------------------------------------------
  // Co-signing
  // ---------------------------------------------------------------

  /**
   * Co-signs the owner-signed PSBT for a matured withdrawal request. The
   * owner's valid signatures on every input are the confirmation step.
   */
  signWithdrawal(identity: string, head: string, requestId: number, psbtBase64: string): string {
    const a = this.requireAccount(identity);
    const before = this.snapshot(identity);
    this.requireHead(a, head);
    const now = this.now();
    const r = requestById(a, requestId);
    if (!r || r.status === 'cancelled') throw new SignerError('bad_request', 'no pending request with this id');
    if (a.locked) throw new SignerError('locked', 'the vault is locked');
    if (isAnnulled(a, r)) throw new SignerError('annulled', 'a lock after this request voided it');
    const allowed = a.allowlist[r.to];
    if (!allowed || allowed.activeAt > now || voidedByLock(a, allowed) || allowed.epoch !== r.addressEpoch) {
      throw new SignerError('address_revoked', 'destination is no longer allowlisted');
    }
    if (now < r.availableAt) throw new SignerError('too_early', 'withdrawal delay has not elapsed');
    if (now > r.expiresAt) throw new SignerError('expired', 'confirmation window has passed');

    const psbt = this.checkedPsbt(a, psbtBase64);
    const toScript = this.parseAddress(r.to).toString('hex');
    const outputs = psbt.txOutputs;
    const payments = outputs.map((o, i) => i).filter(i => outputs[i].script.toString('hex') === toScript);
    if (payments.length !== 1 || outputs[payments[0]].value !== r.amount) {
      throw new SignerError('bad_outputs', 'transaction must pay exactly the requested amount to the requested address once');
    }
    for (const [i, o] of outputs.entries()) {
      if (i !== payments[0] && !this.isAllowedChange(a, o.script)) {
        throw new SignerError('bad_outputs', 'every other output must return to this vault');
      }
    }
    const inputs = psbt.txInputs.map(x => `${Buffer.from(x.hash).reverse().toString('hex')}:${x.index}`).sort();
    if (r.status === 'signed') {
      // A fee bump must spend exactly the same coins, so every signed
      // version conflicts with the others and at most one can confirm.
      if (inputs.join() !== r.signedInputs!.join()) {
        throw new SignerError('bad_request', 'this request is already signed; a replacement must spend the same inputs');
      }
    }
    this.sign(psbt);
    r.status = 'signed';
    r.signedInputs = inputs;
    this.advance(a, { signWithdrawal: requestId, tx: txSummary(psbt) });
    this.commit(identity, before);
    return psbt.toBase64();
  }

  /** Co-signs a move of vault coins into this account's own vault generations. */
  /**
   * Persists the state after an operation. If writing fails, the account is
   * rolled back in memory too and the operation fails: otherwise the client
   * gets an error, the change stays live until a restart and then vanishes.
   */
  private commit(identity: string, before: string | undefined) {
    try {
      this.options.onChange?.(this.state);
    } catch (e) {
      if (before === undefined) delete this.state.accounts[identity];
      else this.state.accounts[identity] = normalizeAccount(JSON.parse(before));
      throw new SignerError('storage', 'the signer could not save this change; nothing was applied');
    }
  }

  private snapshot(identity: string): string | undefined {
    const a = Object.hasOwn(this.state.accounts, identity) ? this.state.accounts[identity] : undefined;
    return a === undefined ? undefined : JSON.stringify(a);
  }

  signRefresh(identity: string, head: string, psbtBase64: string): string {
    const a = this.requireAccount(identity);
    const before = this.snapshot(identity);
    this.requireHead(a, head);
    const now = this.now();
    const psbt = this.checkedPsbt(a, psbtBase64);
    for (const o of psbt.txOutputs) {
      if (!this.isAllowedChange(a, o.script)) throw new SignerError('bad_outputs', 'refresh may only pay into this vault');
    }
    const refreshEvery = a.locked ? lockedInterval(a, this.blockSeconds) : REFRESH_INTERVAL;
    if (a.lastRefreshAt !== undefined && now < a.lastRefreshAt + refreshEvery) {
      throw new SignerError('too_early', a.locked ? `while locked, refreshes are limited to one per ${Math.round(refreshEvery / 86400)} days` : 'refreshes are limited to one per day');
    }
    this.sign(psbt);
    a.lastRefreshAt = now;
    this.advance(a, { signRefresh: now, tx: txSummary(psbt) });
    this.commit(identity, before);
    return psbt.toBase64();
  }

  // ---------------------------------------------------------------
  // Helpers
  // ---------------------------------------------------------------

  private requireAccount(identity: string): Account {
    const a = this.state.accounts[identity];
    if (!a) throw new SignerError('unknown_account', 'account is not registered');
    return a;
  }

  private reportDuress(account: string) {
    // Never awaited and never allowed to fail the operation: the response
    // must look identical with or without duress.
    try {
      this.options.onDuress?.(account);
      const a = this.state.accounts[account];
      const now = this.now();
      if (a) settleSos(a, now);
      if (a?.sosUrl && (a.lastSosAt === undefined || now >= a.lastSosAt + SOS_INTERVAL)) {
        a.lastSosAt = now;
        (this.options.sendSos ?? postSos)(a.sosUrl, { event: 'avelock-duress', account, at: now });
      }
    } catch { /* ignore */ }
  }

  private parseAddress(address: string): Buffer {
    try {
      return bitcoin.address.toOutputScript(address, this.options.network);
    } catch {
      throw new SignerError('bad_address', 'invalid address for this network');
    }
  }

  /** Builds and validates a generation against the account's current policy. */
  private generation(config: VaultConfig, account: Account): Generation {
    if (!config.signers.includes(this.publicKey)) throw new SignerError('bad_vault', 'vault does not include this signer');
    // Every generation's owner key must come from the owner's own account
    // xpub. Otherwise someone holding the seed could register a vault keyed
    // to a key only they hold, refresh everything into it, and lock the
    // real owner out until the reserve door lets them take it all.
    let expected: string;
    try {
      expected = ownerPublicKey(account.accountXpub, this.options.network, config.generation).toString('hex');
    } catch {
      throw new SignerError('bad_vault', 'invalid account xpub or generation');
    }
    if (config.owner !== expected) throw new SignerError('bad_vault', 'owner key is not derived from the account xpub');
    const vault = createVault({
      owner: Buffer.from(config.owner, 'hex'),
      signers: config.signers.map(s => Buffer.from(s, 'hex')),
      threshold: config.threshold,
      reserveBlocks: config.reserveBlocks,
      heir: config.heir ? Buffer.from(config.heir, 'hex') : undefined,
      heirBlocks: config.heirBlocks,
      network: this.options.network,
    });
    const g: Generation = { ...config, address: vault.address, output: vault.output.toString('hex') };
    if (!this.meetsPolicy(g, account)) throw new SignerError('weak_vault', 'vault is weaker than or differs from the current policy');
    return g;
  }

  /**
   * A policy must admit every future renewal: its terms have to build a real
   * vault with the account's signers and each owner key the account can
   * still use. Otherwise a thief with the phrase could schedule a policy no
   * renewal can meet (an heir equal to the signer or a future owner key, or
   * off the curve) and wait for the reserve door (review of H-2).
   */
  private validateBuildable(a: Account, p: Policy) {
    const base = a.generations[0];
    if (!base) return;
    const t = effectiveTerms(p, base);
    const used = Math.max(...a.generations.map(g => g.generation));
    const ownerAt = (gen: number) => {
      try {
        return ownerPublicKey(a.accountXpub, this.options.network, gen);
      } catch {
        throw new SignerError('bad_policy', 'invalid account xpub');
      }
    };
    // One trial build covers the key formats, curve points and the signer set.
    try {
      createVault({
        owner: ownerAt(used + 1),
        signers: t.signers.map(s => Buffer.from(s, 'hex')),
        threshold: t.threshold ?? NaN, // undefined is refused by validateTerms and here
        reserveBlocks: t.reserveBlocks,
        heir: t.heir ? Buffer.from(t.heir, 'hex') : undefined,
        heirBlocks: t.heirBlocks,
        network: this.options.network,
      });
    } catch (e: any) {
      throw new SignerError('bad_policy', `no vault can be built under this policy: ${e?.message ?? e}`);
    }
    // The heir must also differ from the owner keys of upcoming renewals.
    // HEIR_KEY_LOOKAHEAD renewals (~25 years at one per quarter) keeps this
    // to one xpub derivation plus a hundred child keys, not a server stall.
    if (t.heir) {
      let keys: Buffer[];
      try {
        keys = ownerPublicKeys(a.accountXpub, this.options.network, used + 2, used + 2 + HEIR_KEY_LOOKAHEAD);
      } catch {
        throw new SignerError('bad_policy', 'invalid account xpub');
      }
      if (keys.some(k => k.toString('hex') === t.heir)) throw new SignerError('bad_policy', 'the heir key is one of your own vault keys');
    }
  }

  /**
   * A generation may receive coins only if it is at least as strong as the
   * first generation's terms under the current policy: same signer set,
   * reserve door no shorter, and no new or different heir.
   */
  private meetsPolicy(g: VaultConfig, a: Account): boolean {
    const base = a.generations[0] ?? g;
    const t = effectiveTerms(a.policy, base);
    const gSigners = [...g.signers].sort();
    const sameSigners = gSigners.length === t.signers.length && gSigners.every((k, i) => k === t.signers[i]) && g.threshold === t.threshold;
    // Terms must equal the current policy exactly. "No shorter" would let a
    // thief move coins into a generation whose reserve door opens only in
    // ~455 days, instantly, without any policy delay.
    const heirOk = g.heir === t.heir && g.heirBlocks === t.heirBlocks;
    // The reserve door can never be shorter than generation 0's (permanent floor).
    return sameSigners && g.reserveBlocks === t.reserveBlocks && g.reserveBlocks >= base.reserveBlocks && heirOk;
  }

  private isAllowedChange(a: Account, script: Buffer): boolean {
    const hex = script.toString('hex');
    const g = a.generations.find(x => x.output === hex);
    return !!g && this.meetsPolicy(g, a);
  }

  /**
   * Common PSBT checks: every input spends this account's vault through
   * the cosigned leaf with this signer, carries the owner's valid
   * signature, and the fee is within the policy cap. Taproot signatures
   * commit to every input amount and script (BIP-341), so misreported
   * witnessUtxo values invalidate the owner's signature.
   */
  private vaultOf(g: VaultConfig) {
    return createVault({
      owner: Buffer.from(g.owner, 'hex'),
      signers: g.signers.map(k => Buffer.from(k, 'hex')),
      threshold: g.threshold,
      reserveBlocks: g.reserveBlocks,
      heir: g.heir ? Buffer.from(g.heir, 'hex') : undefined,
      heirBlocks: g.heirBlocks,
      network: this.options.network,
    });
  }

  private checkedPsbt(a: Account, base64: string): bitcoin.Psbt {
    let psbt: bitcoin.Psbt;
    try {
      psbt = bitcoin.Psbt.fromBase64(base64, { network: this.options.network });
    } catch {
      throw new SignerError('bad_psbt', 'cannot parse PSBT');
    }
    if (psbt.inputCount === 0) throw new SignerError('bad_psbt', 'no inputs');
    let inputTotal = 0;
    psbt.data.inputs.forEach((input, i) => {
      const utxo = input.witnessUtxo;
      const g = utxo && a.generations.find(x => x.output === utxo.script.toString('hex'));
      if (!utxo || !g) throw new SignerError('bad_inputs', `input ${i} is not from this vault`);
      // The leaf must be a cosigned door of this generation that needs this
      // signer (1-of-1, or one of the pairs of a 2-of-3 vault).
      const leaf = input.tapLeafScript?.[0];
      const doors = this.vaultOf(g).leaves.filter(l => l.door === 'cosigned' && l.signers!.some(k => k.equals(this.options.key.publicKey)));
      if (!leaf || input.tapLeafScript!.length !== 1 || !doors.some(l => l.script.equals(leaf.script))) {
        throw new SignerError('bad_inputs', `input ${i} does not use this signer's cosigned door`);
      }
      // Only SIGHASH_DEFAULT/ALL: anything weaker would let the other party
      // change outputs after the signer has signed.
      if (input.sighashType !== undefined && input.sighashType !== bitcoin.Transaction.SIGHASH_DEFAULT
        && input.sighashType !== bitcoin.Transaction.SIGHASH_ALL) {
        throw new SignerError('bad_sighash', `input ${i} requests a sighash type that does not commit to all outputs`);
      }
      const ownerKey = Buffer.from(g.owner, 'hex');
      const hasOwnerSig = (input.tapScriptSig ?? []).some(s => s.pubkey.equals(ownerKey));
      if (!hasOwnerSig || !psbt.validateSignaturesOfInput(i, schnorrValidator, ownerKey)) {
        throw new SignerError('not_confirmed', `input ${i} lacks a valid owner signature`);
      }
      inputTotal += utxo.value;
    });
    const outputTotal = psbt.txOutputs.reduce((s, o) => s + o.value, 0);
    const fee = inputTotal - outputTotal;
    if (fee < 0 || fee > a.policy.maxFee) throw new SignerError('bad_fee', `fee ${fee} exceeds the policy cap`);
    return psbt;
  }

  private sign(psbt: bitcoin.Psbt) {
    const key = { ...this.options.key, sign: () => { throw new Error('ECDSA signing is not supported'); } };
    for (let i = 0; i < psbt.inputCount; i++) psbt.signTaprootInput(i, key);
  }
}

/** Applies a queued SOS change whose wait is over. */
function settleSos(a: Account, now: number) {
  if (a.pendingSos && now >= a.pendingSos.effectiveAt) {
    a.sosUrl = a.pendingSos.url ?? undefined;
    a.pendingSos = undefined;
  }
}

function requireUnlocked(a: Account) {
  if (a.locked) throw new SignerError('locked', 'the vault is locked');
}

function requireXOnly(key: string) {
  if (!/^[0-9a-f]{64}$/.test(key)) throw new SignerError('bad_guard', 'a guard is an x-only public key (64 hex characters)');
}

function requireGuard(a: Account, key: string): GuardKey {
  requireXOnly(key);
  const g = a.guards && Object.hasOwn(a.guards, key) ? a.guards[key] : undefined;
  if (!g) throw new SignerError('bad_guard', 'no such guard');
  return g;
}

/**
 * Panic Lock: instant (owner or guard). Voids pending requests and waiting
 * destinations (by lock epoch), cancels a queued policy change and waiting
 * guards. Locking again extends the wait; only the owner lifts it, after
 * the lock delay. Refreshes into the vault's own generations still work.
 */
function lock(a: Account, now: number) {
  const until = now + lockDelayOf(a.policy);
  if (a.locked) {
    a.unlockAfter = Math.max(a.unlockAfter ?? 0, until);
    return;
  }
  a.locked = true;
  a.unlockAfter = until;
  a.lockEpoch = (a.lockEpoch ?? 0) + 1;
  (a.lockTimes ??= {})[a.lockEpoch] = now;
  a.pendingPolicy = undefined;
  a.pendingSos = undefined;
  for (const [key, g] of Object.entries(a.guards ?? {})) {
    if (now < g.activeAt) delete a.guards![key];
    else g.removableAt = undefined; // a queued removal is void too (A15-1)
  }
}

/** Still waiting when the first lock after it came. */
export function voidedByLock(a: Pick<Account, 'lockEpoch' | 'lockTimes'>, entry: { activeAt: number; lockEpoch?: number }): boolean {
  const lockedAt = a.lockTimes?.[(entry.lockEpoch ?? 0) + 1];
  return lockedAt !== undefined && lockedAt < entry.activeAt;
}

export function isAnnulled(a: Pick<Account, 'lockEpoch'>, r: WithdrawalRequest): boolean {
  return r.status !== 'signed' && (r.lockEpoch ?? 0) !== (a.lockEpoch ?? 0);
}

export function requestById(a: Pick<Account, 'requests' | 'requestBase'>, id: number): WithdrawalRequest | undefined {
  return Number.isSafeInteger(id) ? a.requests[id - (a.requestBase ?? 0)] : undefined;
}

function txSummary(psbt: bitcoin.Psbt) {
  return {
    inputs: psbt.txInputs.map(x => `${Buffer.from(x.hash).reverse().toString('hex')}:${x.index}`),
    outputs: psbt.txOutputs.map(o => `${o.script.toString('hex')}:${o.value}`),
  };
}

function schnorrValidator(pubkey: Buffer, msghash: Buffer, signature: Buffer): boolean {
  return ecc.verifySchnorr(msghash, pubkey, signature);
}

export function validateFloors(f: Floors, p: Policy) {
  const ok = (v: number) => Number.isInteger(v) && v >= 1 && v <= MAX_DELAY;
  if (!f || !ok(f.withdrawalDelay) || !ok(f.addressDelay)) throw new SignerError('bad_policy', 'floors must be positive delays');
  if (p.withdrawalDelay < f.withdrawalDelay || p.addressDelay < f.addressDelay) {
    throw new SignerError('below_floor', 'delays cannot go below the permanent minimums');
  }
  // Every policy change waits policyDelay, so it needs a floor too: without one a
  // thief shortens it and then lifts maxFee, and a renewal (co-signed at once)
  // pays the balance to miners. An honest withdrawal to a new address waits both
  // minimums in turn, so the floor is their sum (audit A3-2), capped by MAX_DELAY;
  // queuePolicyWait() applies the full sum even where the cap bites.
  if (p.policyDelay < Math.min(f.withdrawalDelay + f.addressDelay, MAX_DELAY)) {
    throw new SignerError('below_floor', 'the settings change delay cannot go below the permanent minimums');
  }
  if (p.lockDelay !== undefined && p.lockDelay < f.withdrawalDelay) {
    throw new SignerError('below_floor', 'the lock delay cannot go below the withdrawal delay minimum');
  }
}

/**
 * The reserve door's length at registration (generation 0) is a permanent
 * floor, like the delay minimums: a policy can lengthen it, never shorten
 * it. The heir door must exceed the reserve door, so it is bounded too.
 */
export function validateReserveFloor(a: Account, p: Policy) {
  const floor = a.generations[0]?.reserveBlocks;
  if (floor !== undefined && p.reserveBlocks !== undefined && p.reserveBlocks < floor) {
    throw new SignerError('below_floor', 'the reserve period cannot go below its permanent minimum');
  }
}

export function validatePolicy(p: Policy) {
  const inRange = (v: number, max: number) => Number.isInteger(v) && v >= 1 && v <= max;
  if (!inRange(p.withdrawalDelay, MAX_DELAY) || !inRange(p.addressDelay, MAX_DELAY) || !inRange(p.policyDelay, MAX_DELAY)) {
    throw new SignerError('bad_policy', `delays must be 1..${MAX_DELAY} seconds`);
  }
  if (!inRange(p.confirmationWindow, MAX_CONFIRMATION_WINDOW)) {
    throw new SignerError('bad_policy', `confirmationWindow must be 1..${MAX_CONFIRMATION_WINDOW} seconds`);
  }
  if (!Number.isSafeInteger(p.maxFee) || p.maxFee < 0) throw new SignerError('bad_policy', 'maxFee must be a non-negative integer');
  if (p.lockDelay !== undefined && !inRange(p.lockDelay, MAX_DELAY)) throw new SignerError('bad_policy', `lockDelay must be 1..${MAX_DELAY} seconds`);
  for (const blocks of [p.reserveBlocks, p.heirBlocks]) {
    if (blocks !== undefined && !inRange(blocks, 0xffff)) throw new SignerError('bad_policy', 'block delays must be 1..65535');
  }
  if (p.heir != null && !/^[0-9a-f]{64}$/.test(p.heir)) throw new SignerError('bad_policy', 'heir must be an x-only hex key');
}

/** Vault terms new generations must meet: explicit policy values, else generation 0's. */
export function effectiveTerms(p: Policy, base: VaultConfig) {
  const heir = p.heir === undefined ? base.heir : p.heir ?? undefined;
  const signers = [...(p.signers ?? base.signers)].sort();
  return {
    signers,
    // No default (A13-7b): a new signer set must state its threshold.
    threshold: p.threshold ?? (p.signers ? undefined : base.threshold),
    reserveBlocks: p.reserveBlocks ?? base.reserveBlocks,
    heir,
    // Without an heir there is no heir door, so no heir period either.
    heirBlocks: heir ? p.heirBlocks ?? base.heirBlocks : undefined,
  };
}

/**
 * The resulting terms must describe a vault createVault can build: heir and
 * heir period together, heir period longer than the reserve period. A policy
 * that no vault can meet would block every renewal until the reserve door
 * opens — a lock-out a thief could schedule.
 */
/**
 * Shortest reserve door on the main networks (audit A13-4): at least two
 * locked renewal intervals, so a locked vault is renewed in time without
 * renewals frequent enough for a phrase thief to burn its fees (NEW-M6).
 */
export const MIN_RESERVE_SECONDS_MAINNET = 2 * REFRESH_INTERVAL_LOCKED;

export function validateTerms(t: ReturnType<typeof effectiveTerms>, self?: string, minReserveBlocks = 1) {
  if (t.reserveBlocks < minReserveBlocks) throw new SignerError('bad_policy', `the reserve period must be at least ${minReserveBlocks} blocks`);
  if (!t.signers.length || new Set(t.signers).size !== t.signers.length || t.signers.some(k => !/^[0-9a-f]{64}$/.test(k))) {
    throw new SignerError('bad_policy', 'signers must be distinct x-only keys');
  }
  if (self && !t.signers.includes(self)) throw new SignerError('bad_policy', 'this signer must stay in the signer set');
  // Several signers only as a threshold of at least two: "any one of three"
  // would let one compromised signer act alone.
  const minThreshold = t.signers.length === 1 ? 1 : 2;
  if (t.threshold === undefined || !Number.isInteger(t.threshold) || t.threshold < minThreshold || t.threshold > t.signers.length) {
    throw new SignerError('bad_policy', `threshold must be between ${minThreshold} and ${t.signers.length}`);
  }
  if ((t.heir == null) !== (t.heirBlocks == null)) throw new SignerError('bad_policy', 'heir and heirBlocks go together');
  if (t.heirBlocks != null && t.heirBlocks <= t.reserveBlocks) {
    throw new SignerError('bad_policy', 'the heir period must be longer than the reserve period');
  }
}


/**
 * Maps keyed by client-supplied strings (accounts, addresses, guard keys) have
 * no prototype, so a key such as "__proto__" is an ordinary entry and can never
 * reach Object.prototype of the signer process (audit A3-1).
 */
function dict<T>(entries?: Record<string, T>): Record<string, T> {
  return Object.assign(Object.create(null), entries ?? {});
}

function normalizeAccount(a: Account): Account {
  a.allowlist = dict(a.allowlist);
  a.addressEpochs = dict(a.addressEpochs);
  if (a.guards) a.guards = dict(a.guards);
  return a;
}

function normalizeState(state: SignerState): SignerState {
  state.accounts = dict(state.accounts);
  for (const a of Object.values(state.accounts)) normalizeAccount(a);
  return state;
}

/**
 * How long a queued policy change waits: the current policyDelay, but never
 * less than both delay minimums in turn (audit A3-2), nor than the current
 * withdrawal delay (audit A15-2, as A14-2 in the contracts): otherwise an
 * owner's 30-day delay could be lowered after the minimums (say 8 days) and
 * a withdrawal made sooner than the delay the owner set; the same path would
 * raise the fee cap.
 */
export function policyWait(a: Account): number {
  return Math.max(a.policy.policyDelay, a.floors.withdrawalDelay + a.floors.addressDelay, a.policy.withdrawalDelay);
}
