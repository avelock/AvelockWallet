// Self-hostable signer HTTP server.
//
//   POST /op                 SignedOperation                   -> result + head
//   POST /sign/withdrawal    { account, head, requestId, psbt } -> { psbt, head }
//   POST /sign/refresh       { account, head, psbt }           -> { psbt, head }
//   POST /account            SignedRead                        -> account state (owner only)
//   GET  /info                                                 -> { publicKey, network }
//
// State is a JSON file written atomically after every change. The signer
// key is a 32-byte hex secret in its own file, generated on first start;
// it must never be derived from any owner seed.

import * as bitcoin from 'bitcoinjs-lib';
import * as ecc from '@bitcoinerlab/secp256k1';
import { randomBytes } from 'crypto';
import { createServer, IncomingMessage, Server, ServerResponse } from 'http';
import { closeSync, existsSync, fsyncSync, openSync, readFileSync, renameSync, writeFileSync, writeSync } from 'fs';
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

export function createSignerServer(options: ServerOptions): { server: Server; signer: SignerService } {
  const statePath = join(options.dataDir, 'state.json');
  const state: SignerState | undefined = existsSync(statePath) ? JSON.parse(readFileSync(statePath, 'utf8')) : undefined;
  const signer = new SignerService({
    key: loadOrCreateKey(options.dataDir),
    network: options.network,
    networkName: options.networkName,
    now: options.now,
    state,
    onChange: s => writeAtomic(statePath, JSON.stringify(s)),
    onDuress: options.onDuress,
  });

  const registrations = new Map<string, number[]>();
  const allowRegistration = (ip: string) => {
    const now = Date.now();
    // Forget clients idle for an hour, so the table can't grow without end.
    if (registrations.size > 10_000) {
      for (const [k, times] of registrations) if (times[times.length - 1] <= now - 3_600_000) registrations.delete(k);
    }
    const key = clientKey(ip);
    const recent = (registrations.get(key) ?? []).filter(t => t > now - 3_600_000);
    if (recent.length >= (options.registrationsPerIp ?? REGISTRATIONS_PER_IP)) return false;
    registrations.set(key, [...recent, now]);
    return true;
  };

  // The co-signing event comes back with the new head, so the client can
  // check it extends the head it sent (audit M-8).
  const signed = (account: string, psbt: string) => {
    const head = signer.getAccount(account)!.head;
    return { psbt, head, events: signer.eventsAfter(account, head.seq - 1) };
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
          if (body?.body?.operation?.op === 'register' && !allowRegistration(clientAddress(req, options.behindProxy ?? true))) {
            return send(res, 429, { error: 'rate_limited', message: 'too many new accounts from this address' });
          }
          return send(res, 200, signer.submit(body));
        }
        case '/account': return send(res, 200, signer.readAccount(body));
        // Guard keys: stop-only operations and the state they watch.
        case '/guard': return send(res, 200, signer.guardSubmit(body));
        case '/sign/withdrawal': {
          const psbt = signer.signWithdrawal(body.account, body.head, body.requestId, body.psbt);
          return send(res, 200, signed(body.account, psbt));
        }
        case '/sign/refresh': {
          const psbt = signer.signRefresh(body.account, body.head, body.psbt);
          return send(res, 200, signed(body.account, psbt));
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
  const { server, signer } = createSignerServer({ dataDir, network, networkName: net as NetworkName });
  server.listen(Number(port), '127.0.0.1', () => {
    console.log(`Avelock signer ${signer.publicKey} on ${net}, listening on 127.0.0.1:${port}`);
  });
}
