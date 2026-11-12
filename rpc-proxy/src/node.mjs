// The same proxy on a plain server (fallback where Cloudflare is not
// reachable). Listens on 127.0.0.1 behind nginx (TLS). Keys come from the
// environment (systemd EnvironmentFile, mode 600). No request logging.
import { createServer } from 'node:http';
import { pathToFileURL } from 'node:url';
import { handle, limitKey, MAX_BODY } from './proxy.mjs';

const PER_MINUTE = Number(process.env.RATE_PER_MINUTE || 120);
/** Shared by every client of one route (round2 H-1). */
const SHARED_PER_MINUTE = Number(process.env.SHARED_PER_MINUTE || 3000);

// One minute of counts per client (IPv6 by /64); the table is dropped when
// the minute changes (A8-7) and holds at most MAX_KEYS within one (round2 L-8).
const MAX_KEYS = 100_000;
let minute = -1;
let hits = new Map();
let routeHits = new Map();
function sharedLimited(route, weight) {
  const now = Math.floor(Date.now() / 60_000);
  if (now !== minute) { minute = now; hits = new Map(); routeHits = new Map(); }
  const n = (routeHits.get(route) ?? 0) + weight;
  routeHits.set(route, n);
  return n > SHARED_PER_MINUTE;
}
function limited(ip, weight = 1) {
  const now = Math.floor(Date.now() / 60_000);
  if (now !== minute) { minute = now; hits = new Map(); routeHits = new Map(); }
  const key = limitKey(ip);
  if (!hits.has(key) && hits.size >= MAX_KEYS) return true;
  const n = (hits.get(key) ?? 0) + weight;
  hits.set(key, n);
  return n > PER_MINUTE;
}
/** Largest answer passed on (round2 L-4): past it the connection is cut. */
const MAX_ANSWER = 8 * 1024 * 1024;

class BadRequest extends Error {}

/**
 * One request. Nothing a client or a provider does can crash the process
 * (A8-6): a broken upload or an odd method is a 400, a failing answer a 502.
 */
export async function nodeHandler(req, res, env = process.env) {
  const reply = (status, headers = {}) => {
    if (!res.headersSent) res.writeHead(status, headers);
    res.end();
  };
  try {
    if (req.method !== 'GET' && req.method !== 'POST') throw new BadRequest();
    // nginx passes the client address; the header is believed only from a
    // loopback peer, which is nginx (round2 L-7).
    const peer = String(req.socket.remoteAddress ?? '');
    const loopback = peer === '127.0.0.1' || peer === '::1' || peer === '::ffff:127.0.0.1';
    const ip = loopback && typeof req.headers['x-real-ip'] === 'string' ? req.headers['x-real-ip'] : peer;
    if (limited(ip)) return reply(429, { 'Retry-After': '60' });
    const chunks = [];
    let size = 0;
    try {
      for await (const c of req) {
        size += c.length;
        if (size > MAX_BODY) return reply(413);
        chunks.push(c);
      }
    } catch {
      throw new BadRequest();
    }
    const request = new Request(`http://proxy${req.url}`, {
      method: req.method,
      headers: { 'content-type': req.headers['content-type'] || '' },
      body: req.method === 'POST' ? Buffer.concat(chunks) : undefined,
    });
    const response = await handle(request, env, fetch, async n => !limited(ip, n), async (route, w) => !sharedLimited(route, w));
    // Streamed with a byte count (round2 L-4): a huge answer is cut, not held in memory.
    res.writeHead(response.status, Object.fromEntries(response.headers));
    if (!response.body) return void res.end();
    let sent = 0;
    for await (const chunk of response.body) {
      sent += chunk.byteLength;
      if (sent > MAX_ANSWER) return void res.destroy();
      if (!res.write(chunk)) await new Promise(r => res.once('drain', r));
    }
    res.end();
  } catch (e) {
    reply(e instanceof BadRequest ? 400 : 502);
  }
}

export function serve(port = Number(process.env.PORT || 8899), host = '127.0.0.1') {
  return createServer((req, res) => { void nodeHandler(req, res); }).listen(port, host);
}

if (import.meta.url === pathToFileURL(process.argv[1] ?? '').href) serve();
