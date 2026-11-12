// Self-hostable signer HTTP server.
//
//   POST /op                 SignedOperation                   -> result + head
//   POST /sign/withdrawal    { account, head, requestId, psbt } -> { psbt, head }
//   POST /sign/refresh       { account, head, psbt }           -> { psbt, head }
//   POST /account            SignedRead                        -> account state (owner only)
//   POST /guard              SignedGuardOperation              -> result / state for a guard key
//   GET  /info                                                 -> { publicKey, network }
//
// State is a JSON file written atomically after every change. The signer
// key is a 32-byte hex secret in its own file, generated on first start;
// it must never be derived from any owner seed.

import * as bitcoin from 'bitcoinjs-lib';
import * as ecc from '@bitcoinerlab/secp256k1';
import { randomBytes } from 'crypto';
import { createServer, IncomingMessage, Server, ServerResponse } from 'http';
import { closeSync, existsSync, fsyncSync, mkdirSync, openSync, readdirSync, readFileSync, renameSync, rmSync, writeFileSync, writeSync } from 'fs';
import { dirname, join } from 'path';
import { isIP } from 'net';
import { taprootSigner } from '../keys';
import { SignerError, SignerService, SignerState } from './service';
import type { NetworkName } from './messages';
import { litecoin, litecoinTestnet } from '../networks';

export interface ServerOptions {
  dataDir: string;
  network: bitcoin.Network;
  networkName: NetworkName;
  now?: () => number;
  /** Duress hook (the account's SOS URL, if set, is notified separately). */
  onDuress?: (account: string) => void;
  /** New accounts per client IP per hour (default REGISTRATIONS_PER_IP). */
  registrationsPerIp?: number;
  /**
   * The server listens on loopback behind a reverse proxy, so every client
   * arrives from 127.0.0.1 (audit A15-5). For a connection from loopback the
   * client is the last X-Forwarded-For hop, the one the proxy appended; a
   * header from anyone else is ignored. Default true; false when clients
   * connect directly.
   */
  behindProxy?: boolean;
  /**
   * Where the high-water mark lives (round2 L-6). Default `<dataDir>/state.mark`;
   * put it on another disk or host path so that restoring `state.json` from
   * a backup does not restore the mark with it.
   */
  markPath?: string;
}

/** Grows with every saved change: account heads only move forward. */
export function stateVersion(state: SignerState | undefined): number {
  if (!state) return 0;
  return Object.values(state.accounts).reduce((n, a) => n + a.head.seq + 1, 0);
}

const MAX_BODY = 1_000_000;
export const REGISTRATIONS_PER_IP = 5;

const LOOPBACK = /^(127\.\d+\.\d+\.\d+|::1|::ffff:127\.\d+\.\d+\.\d+)$/i;

/** The client address for rate limits (see ServerOptions.behindProxy). */
export function clientAddress(req: Pick<IncomingMessage, 'socket' | 'headers'>, behindProxy = true): string {
  const peer = req.socket.remoteAddress ?? '';
  if (!behindProxy || !LOOPBACK.test(peer)) return peer;
  const header = req.headers['x-forwarded-for'];
  const hops = (Array.isArray(header) ? header.join(',') : header ?? '').split(',').map(h => h.trim()).filter(Boolean);
  const last = hops[hops.length - 1];
  return last && isIP(last) ? last : peer;
}

export function loadOrCreateKey(dataDir: string) {
  const path = join(dataDir, 'signer.key');
  // A first start in a new data directory makes it (owner-only).
  if (!existsSync(dataDir)) mkdirSync(dataDir, { recursive: true, mode: 0o700 });
  if (!existsSync(path)) writeFileSync(path, randomBytes(32).toString('hex'), { mode: 0o600, flag: 'wx' });
  const privateKey = Buffer.from(readFileSync(path, 'utf8').trim(), 'hex');
  if (privateKey.length !== 32 || !ecc.isPrivate(privateKey)) throw new Error('invalid signer key file');
  const publicKey = Buffer.from(ecc.pointFromScalar(privateKey, true)!);
  return taprootSigner({ privateKey, publicKey });
}

/**
 * Crash-safe replace: the new state reaches the disk before it takes the
 * old one's place, and the rename itself is flushed (audit M-11). Without
 * the fsyncs a power loss could leave an empty or old file — a silent
 * rollback of delays and cancellations.
 */
function writeAtomic(path: string, data: string) {
  const tmp = `${path}.tmp`;
  const fd = openSync(tmp, 'w', 0o600);
  try {
    writeSync(fd, data);
    fsyncSync(fd);
  } finally {
    closeSync(fd);
  }
  renameSync(tmp, path);
  // After the rename the new state IS the file: failing now would roll the
  // change back in memory while it stays on disk and "comes back" on restart.
  // A failed directory fsync only weakens durability, so it is logged, not thrown.
  try {
    const dir = openSync(dirname(path), 'r');
    try { fsyncSync(dir); } finally { closeSync(dir); }
  } catch (e) {
    console.error('state directory fsync failed; the new state is written but may not survive a power loss', e);
  }
}

const ACCOUNT_FILE = /^([0-9a-f]{64})\.json$/;

/**
 * One file per account (round2 M-4): a change rewrites only its own account,
 * so a large account no longer makes every other account's write slow, and
 * one account can never make the whole state unsavable. An older single
 * `state.json` is split up once, then kept as `state.json.migrated`.
 */
function loadState(dataDir: string): SignerState | undefined {
  const dir = join(dataDir, 'accounts');
  const legacy = join(dataDir, 'state.json');
  if (!existsSync(dir)) {
    if (!existsSync(legacy)) return undefined;
    const old: SignerState = JSON.parse(readFileSync(legacy, 'utf8'));
    // Split into a side directory that takes the real one's place in one
    // rename (REVIEW_last3days): a crash part-way leaves no `accounts`
    // directory, so the next start splits again from state.json instead of
    // loading a partial set and silently losing accounts.
    const tmp = `${dir}.tmp`;
    rmSync(tmp, { recursive: true, force: true });
    mkdirSync(tmp, { recursive: true, mode: 0o700 });
    for (const [id, a] of Object.entries(old.accounts ?? {})) {
      if (!/^[0-9a-f]{64}$/.test(id)) throw new Error(`state.json holds an account with a bad id: ${id.slice(0, 20)}`);
      writeAtomic(join(tmp, `${id}.json`), JSON.stringify(a));
    }
    renameSync(tmp, dir);
    renameSync(legacy, `${legacy}.migrated`);
  }
  const accounts: SignerState['accounts'] = {};
  for (const f of readdirSync(dir)) {
    const m = ACCOUNT_FILE.exec(f);
    if (m) accounts[m[1]] = JSON.parse(readFileSync(join(dir, f), 'utf8'));
  }
  return { accounts };
}

function saveAccount(dataDir: string, state: SignerState, id: string) {
  if (!/^[0-9a-f]{64}$/.test(id)) throw new Error('bad account id');
  const dir = join(dataDir, 'accounts');
  if (!existsSync(dir)) mkdirSync(dir, { recursive: true, mode: 0o700 });
  // An account taken back out (a failed registration) is never on disk: nothing to write.
  const a = state.accounts[id];
  if (a !== undefined) writeAtomic(join(dir, `${id}.json`), JSON.stringify(a));
}

export function createSignerServer(options: ServerOptions): { server: Server; signer: SignerService } {
  const state = loadState(options.dataDir);
  // A state older than the last one saved (restored from a backup) would
  // undo cancellations and locks: refuse to start (round2 L-6). An operator
  // who really means to roll back deletes the mark file by hand.
  const markPath = options.markPath ?? join(options.dataDir, 'state.mark');
  const mark = existsSync(markPath) ? Number(readFileSync(markPath, 'utf8').trim()) : 0;
  if (!Number.isSafeInteger(mark) || stateVersion(state) < mark) {
    throw new Error(`the saved state is older than the last saved state (mark ${mark}, state ${stateVersion(state)}); it may have been restored from a backup. Refusing to start.`);
  }
  const signer = new SignerService({
    key: loadOrCreateKey(options.dataDir),
    network: options.network,
    networkName: options.networkName,
    now: options.now,
    state,
    onChange: (s, changed) => {
      saveAccount(options.dataDir, s, changed);
      // After the state: a crash in between leaves the state ahead of the mark, which is fine.
      writeAtomic(markPath, String(stateVersion(s)));
    },
    onDuress: options.onDuress,
  });

  const registrations = new Map<string, number[]>();
  /** Clients remembered at once: past this, new ones wait (MEGA_AUDIT btc_03 M-2). */
  const MAX_TRACKED = 10_000;
  const allowRegistration = (ip: string) => {
    const now = Date.now();
    // Forget clients idle for an hour, so the table can't grow without end.
    if (registrations.size >= MAX_TRACKED) {
      // Empty entries (refunded) go too (MEGA_AUDIT round2 bitcoin_signer M-3).
      for (const [k, times] of registrations) if (!times.length || times[times.length - 1] <= now - 3_600_000) registrations.delete(k);
    }
    const key = clientKey(ip);
    const recent = (registrations.get(key) ?? []).filter(t => t > now - 3_600_000);
    if (recent.length >= (options.registrationsPerIp ?? REGISTRATIONS_PER_IP)) return false;
    // A flood of fresh identities (spoofed forwarding headers) can't grow it further.
    if (!registrations.has(key) && registrations.size >= MAX_TRACKED) return false;
    registrations.set(key, [...recent, now]);
    return true;
  };
  /** A refused registration does not use up the address's quota (MEGA_AUDIT btc_03 L-3). */
  const refundRegistration = (ip: string) => {
    const key = clientKey(ip);
    const times = registrations.get(key);
    if (times?.length) times.pop();
    // A refused attempt leaves nothing behind: an empty entry would hold a table slot.
    if (times && !times.length) registrations.delete(key);
  };

  // The co-signing event comes back with the new head, so the client can
  // check it extends the head it sent (audit M-8).
  const signed = (account: string, psbt: string) => {
    const head = signer.getAccount(account)!.head;
    return { psbt, head, events: signer.eventsAfter(account, head.seq - 1) };
  };

  /** A 200 reply signed by the signer, bound to the request it answers (mobile_12 MB-1). */
  const ok = (res: ServerResponse, requestSignature: unknown, reply: unknown) => {
    const plain = JSON.parse(JSON.stringify(reply));
    const signerSignature = typeof requestSignature === 'string' ? signer.signReply(requestSignature, plain) : undefined;
    return send(res, 200, { ...plain, signerSignature });
  };

  const server = createServer(async (req, res) => {
    try {
      const url = new URL(req.url ?? '/', 'http://signer');
      if (req.method === 'GET' && url.pathname === '/info') {
        return send(res, 200, { publicKey: signer.publicKey, network: options.networkName });
      }
      if (req.method !== 'POST') return send(res, 404, { error: 'not_found' });
      const body = await readJson(req);
      switch (url.pathname) {
        case '/op': {
          if (body?.body?.operation?.op === 'register') {
            const ip = clientAddress(req, options.behindProxy ?? true);
            if (!allowRegistration(ip)) return send(res, 429, { error: 'rate_limited', message: 'too many new accounts from this address' });
            try {
              return ok(res, body?.signature, signer.submit(body));
            } catch (e) {
              refundRegistration(ip);
              throw e;
            }
          }
          return ok(res, body?.signature, signer.submit(body));
        }
        case '/account': return ok(res, body?.signature, signer.readAccount(body));
        // Guard keys: stop-only operations and the state they watch.
        case '/guard': return ok(res, body?.signature, signer.guardSubmit(body));
        // Owner-signed (MEGA_AUDIT btc_02 F1): { request: SignedCosign, psbt }.
        case '/sign/withdrawal': {
          const op = signer.verifyCosign(body?.request, 'cosignWithdrawal', body?.psbt) as { requestId: number; head: string };
          const account = body.request.body.account;
          const psbt = signer.signWithdrawal(account, op.head, op.requestId, body.psbt);
          return ok(res, body.request.signature, signed(account, psbt));
        }
        case '/sign/refresh': {
          const op = signer.verifyCosign(body?.request, 'cosignRefresh', body?.psbt);
          const account = body.request.body.account;
          const psbt = signer.signRefresh(account, op.head, body.psbt);
          return ok(res, body.request.signature, signed(account, psbt));
        }
        default: return send(res, 404, { error: 'not_found' });
      }
    } catch (e) {
      if (e instanceof SignerError) return send(res, 400, { error: e.code, message: e.message });
      return send(res, 400, { error: 'bad_request', message: 'malformed request' });
    }
  });
  return { server, signer };
}

/**
 * Who counts as one client for the registration limit: an IPv4 address, or
 * an IPv6 /64 — one household or server usually holds a whole /64, so
 * per-address limits would be trivial to step around.
 */
export function clientKey(ip: string): string {
  const mapped = ip.match(/^::ffff:(\d+\.\d+\.\d+\.\d+)$/i);
  if (mapped) return mapped[1];
  if (isIP(ip) !== 6) return ip;
  const [head, tail = ''] = ip.toLowerCase().split('::');
  const left = head ? head.split(':') : [];
  const right = tail ? tail.split(':') : [];
  const groups = ip.includes('::') ? [...left, ...Array(8 - left.length - right.length).fill('0'), ...right] : left;
  return groups.slice(0, 4).map(g => g.padStart(4, '0')).join(':') + '::/64';
}

function send(res: ServerResponse, status: number, body: unknown) {
  res.writeHead(status, { 'Content-Type': 'application/json' });
  res.end(JSON.stringify(body));
}

function readJson(req: IncomingMessage): Promise<any> {
  return new Promise((resolve, reject) => {
    let size = 0;
    const chunks: Buffer[] = [];
    // The whole body within 10 s, however it trickles in (round2 L-7): a
    // socket idle timeout restarts on every byte.
    const deadline = setTimeout(() => { reject(new Error('body timed out')); req.destroy(); }, 10_000);
    req.on('close', () => clearTimeout(deadline));
    req.on('data', (c: Buffer) => {
      size += c.length;
      if (size > MAX_BODY) { reject(new Error('body too large')); req.destroy(); return; }
      chunks.push(c);
    });
    req.on('end', () => {
      try { resolve(JSON.parse(Buffer.concat(chunks).toString('utf8'))); } catch (e) { reject(e); }
    });
    req.on('error', reject);
  });
}

// `node dist/src/signer/server.js <dataDir> <bitcoin|testnet|signet|regtest|litecoin|litecoin-testnet> [port]`
if (require.main === module) {
  const [dataDir = './signer-data', net = 'regtest', port = '8339'] = process.argv.slice(2);
  const networks: Record<NetworkName, bitcoin.Network> = {
    bitcoin: bitcoin.networks.bitcoin, testnet: bitcoin.networks.testnet,
    signet: bitcoin.networks.testnet, regtest: bitcoin.networks.regtest,
    litecoin, 'litecoin-testnet': litecoinTestnet,
  };
  const network = networks[net as NetworkName];
  if (!network) throw new Error(`unknown network ${net}`);
  const { server, signer } = createSignerServer({ dataDir, network, networkName: net as NetworkName, markPath: process.env.SIGNER_MARK_PATH || undefined });
  server.listen(Number(port), '127.0.0.1', () => {
    console.log(`Avelock signer ${signer.publicKey} on ${net}, listening on 127.0.0.1:${port}`);
  });
}
