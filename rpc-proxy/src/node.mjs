// The same proxy on a plain server (fallback where Cloudflare is not
// reachable). Listens on 127.0.0.1 behind nginx (TLS). Keys come from the
// environment (systemd EnvironmentFile, mode 600). No request logging.
import { createServer } from 'node:http';
import { pathToFileURL } from 'node:url';
import { handle, limitKey, MAX_BODY } from './proxy.mjs';

const PER_MINUTE = Number(process.env.RATE_PER_MINUTE || 120);

// One minute of counts per client (IPv6 by /64); the table is dropped when
// the minute changes, so it cannot grow without bound (A8-7).
let minute = -1;
let hits = new Map();
function limited(ip) {
  const now = Math.floor(Date.now() / 60_000);
  if (now !== minute) { minute = now; hits = new Map(); }
  const key = limitKey(ip);
  const n = (hits.get(key) ?? 0) + 1;
  hits.set(key, n);
  return n > PER_MINUTE;
}

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
    // nginx passes the client address; only it can reach this port.
    const ip = String(req.headers['x-real-ip'] || req.socket.remoteAddress);
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
    const response = await handle(request, env);
    const body = Buffer.from(await response.arrayBuffer());
    res.writeHead(response.status, Object.fromEntries(response.headers));
    res.end(body);
  } catch (e) {
    reply(e instanceof BadRequest ? 400 : 502);
  }
}

export function serve(port = Number(process.env.PORT || 8899), host = '127.0.0.1') {
  return createServer((req, res) => { void nodeHandler(req, res); }).listen(port, host);
}

if (import.meta.url === pathToFileURL(process.argv[1] ?? '').href) serve();
