// Network status for status.avelock.app: one cheap read per network, made
// the same way the proxy reaches it (same upstream, same provider key). The
// answer holds only public facts — up or down, latency, latest block — never
// an upstream URL or a key. Results are kept for STATUS_TTL_MS so the page
// cannot spend provider quotas faster than once a minute.

import { routes } from './proxy.mjs';

export const STATUS_TTL_MS = 60_000;
/** A network slower than this is "degraded"; one that does not answer in PROBE_TIMEOUT_MS is "down". */
export const SLOW_MS = 3000;
export const PROBE_TIMEOUT_MS = 8000;

const evmProbe = { method: 'POST', body: { jsonrpc: '2.0', id: 1, method: 'eth_blockNumber', params: [] }, height: j => parseInt(j.result, 16) };

/**
 * What the page shows, in the order it shows it: Bitcoin, Ethereum, Solana,
 * TON, Ethereum's L2s, then the rest. `route` is the proxy route the app uses.
 */
export const NETWORKS = [
  { id: 'btc', name: 'Bitcoin', testnet: 'Signet', route: '/btc/signet', path: '/blocks/tip/height', method: 'GET', text: true, height: t => Number(t) },
  { id: 'eth', name: 'Ethereum', testnet: 'Sepolia', route: '/evm/eth', ...evmProbe },
  { id: 'sol', name: 'Solana', testnet: 'Devnet', route: '/sol/devnet', method: 'POST', body: { jsonrpc: '2.0', id: 1, method: 'getSlot', params: [] }, height: j => j.result },
  { id: 'ton', name: 'TON', testnet: 'Testnet', route: '/ton/testnet', path: '/api/v2/jsonRPC', method: 'POST', body: { jsonrpc: '2.0', id: 1, method: 'getMasterchainInfo', params: {} }, height: j => j.result?.last?.seqno },
  { id: 'base', name: 'Base', testnet: 'Sepolia', route: '/evm/base', ...evmProbe },
  { id: 'arbitrum', name: 'Arbitrum', testnet: 'Sepolia', route: '/evm/arbitrum', ...evmProbe },
  { id: 'optimism', name: 'Optimism', testnet: 'Sepolia', route: '/evm/optimism', ...evmProbe },
  { id: 'polygon', name: 'Polygon', testnet: 'Amoy', route: '/evm/polygon', ...evmProbe },
  { id: 'bnb', name: 'BNB Chain', testnet: 'Testnet', route: '/evm/bnb', ...evmProbe },
  { id: 'avalanche', name: 'Avalanche', testnet: 'Fuji', route: '/evm/avalanche', ...evmProbe },
  { id: 'tron', name: 'Tron', testnet: 'Nile', route: '/tron/nile', path: '/jsonrpc', ...evmProbe },
  { id: 'ltc', name: 'Litecoin', testnet: 'Testnet', route: '/ltc/testnet', path: '/blocks/tip/height', method: 'GET', text: true, height: t => Number(t) },
];

/** Checks one network. Never throws: a failure is a "down" entry. */
async function probe(net, env, fetchUpstream) {
  const route = routes(env).find(r => r.prefix === net.route);
  const base = { id: net.id, name: net.name, testnet: net.testnet };
  if (!route) return { ...base, status: 'down', latencyMs: null, height: null };
  const headers = { Accept: 'application/json' };
  if (net.method === 'POST') headers['Content-Type'] = 'application/json';
  if (route.header) headers[route.header[0]] = route.header[1];
  const started = Date.now();
  try {
    const res = await fetchUpstream(route.upstream + (net.path ?? ''), {
      method: net.method, headers, body: net.body ? JSON.stringify(net.body) : undefined,
      redirect: 'manual', signal: AbortSignal.timeout(PROBE_TIMEOUT_MS),
    });
    const latencyMs = Date.now() - started;
    if (!res.ok) return { ...base, status: 'down', latencyMs, height: null };
    const height = net.height(net.text ? (await res.text()).trim() : await res.json());
    if (!Number.isSafeInteger(height) || height <= 0) return { ...base, status: 'down', latencyMs, height: null };
    return { ...base, status: latencyMs > SLOW_MS ? 'degraded' : 'up', latencyMs, height };
  } catch {
    return { ...base, status: 'down', latencyMs: null, height: null };
  }
}

/** Checks every network at once. */
export async function checkAll(env = {}, fetchUpstream = fetch, now = Date.now) {
  const networks = await Promise.all(NETWORKS.map(n => probe(n, env, fetchUpstream)));
  return { checkedAt: new Date(now()).toISOString(), networks };
}

let cached = null;
/** A check under way: requests arriving meanwhile share it instead of each probing every network. */
let running = null;

/** The status answer, from a fresh check at most once per STATUS_TTL_MS (per Worker instance). */
export async function statusResponse(env = {}, fetchUpstream = fetch, now = Date.now) {
  if (!cached || now() - cached.at >= STATUS_TTL_MS) {
    running ??= checkAll(env, fetchUpstream, now)
      .then(result => { cached = { at: now(), body: JSON.stringify(result) }; })
      .finally(() => { running = null; });
    await running;
  }
  return new Response(cached.body, {
    status: 200,
    headers: {
      'Content-Type': 'application/json',
      'Cache-Control': 'public, max-age=30',
      // Public facts only, read by status.avelock.app.
      'Access-Control-Allow-Origin': '*',
      'X-Content-Type-Options': 'nosniff',
    },
  });
}

/** For tests: forget the cached answer. */
export function resetStatusCache() {
  cached = null;
  running = null;
}
