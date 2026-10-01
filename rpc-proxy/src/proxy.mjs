// Avelock RPC proxy: one handler for Cloudflare Workers and Node.
//
// The app reaches every network through here, so provider API keys stay on
// the proxy (Worker secrets / server env), never in the app. The proxy is
// delivery only and is not trusted: security checks in the app verify
// independently (other RPC operators, proofs, local rebuilds).
//
// Paths mirror the provider's own paths after a route prefix, e.g.
//   /ton/testnet/api/v2/jsonRPC -> https://testnet.toncenter.com/api/v2/jsonRPC
// Only methods and paths the app uses pass; bodies are size-capped; client
// headers other than Content-Type are dropped (no cookies, no client keys).

import { statusResponse } from './status.mjs';

export const MAX_BODY = 128 * 1024;
export const MAX_BATCH = 20;
/** A provider that does not answer in this time gets a 504 (A8-6). */
export const UPSTREAM_TIMEOUT_MS = 15000;

/** GET /v1/accounts/<base58 address>/transactions — read-only history of one account. */
const TRON_HISTORY = /^\/v1\/accounts\/T[1-9A-HJ-NP-Za-km-z]{33}\/transactions$/;
const TRON_PATHS = ['/wallet/broadcasthex', '/wallet/createtransaction', '/wallet/deploycontract', '/wallet/getaccount',
  '/wallet/gettransactioninfobyid', '/wallet/triggersmartcontract'];

const EVM_METHODS = [
  'eth_chainId', 'net_version', 'eth_blockNumber', 'eth_getBalance', 'eth_call', 'eth_getCode', 'eth_getStorageAt',
  'eth_getProof', 'eth_getLogs', 'eth_estimateGas', 'eth_gasPrice', 'eth_maxPriorityFeePerGas', 'eth_feeHistory',
  'eth_getTransactionCount', 'eth_sendRawTransaction', 'eth_getTransactionReceipt', 'eth_getTransactionByHash',
  'eth_getBlockByNumber', 'eth_getBlockByHash',
];
const SOLANA_METHODS = [
  'getAccountInfo', 'getMultipleAccounts', 'getBalance', 'getMinimumBalanceForRentExemption', 'getProgramAccounts',
  'getTokenAccountsByOwner', 'getSignaturesForAddress', 'getTransaction', 'getLatestBlockhash', 'isBlockhashValid',
  'sendTransaction', 'simulateTransaction', 'getSignatureStatuses', 'getBlockHeight', 'getSlot', 'getEpochInfo',
  'getGenesisHash', 'getVersion', 'getFeeForMessage', 'getRecentPrioritizationFees',
];
const TON_V2_METHODS = [
  'getAddressInformation', 'getExtendedAddressInformation', 'getWalletInformation', 'getAddressBalance', 'getAddressState',
  'getTransactions', 'getMasterchainInfo', 'runGetMethod', 'sendBoc', 'sendBocReturnHash', 'estimateFee',
  'tryLocateTx', 'tryLocateResultTx', 'tryLocateSourceTx', 'getConfigParam', 'getShards', 'getBlockHeader', 'lookupBlock',
];

/** Upstreams and rules per route. `key` names the env secret holding the provider key. */
export function routes(env = {}) {
  // Event scans (eth_getLogs over thousands of blocks) go to the public node:
  // free provider plans cap the range (Alchemy: 10 blocks).
  const evm = (name, url) => ({ prefix: `/evm/${name}`, upstream: env[`EVM_${name.toUpperCase()}_URL`] || url, publicUpstream: url, publicMethods: ['eth_getLogs'], kind: 'jsonrpc', methods: EVM_METHODS });
  return [
    evm('eth', 'https://ethereum-sepolia-rpc.publicnode.com'),
    evm('base', 'https://sepolia.base.org'),
    evm('arbitrum', 'https://sepolia-rollup.arbitrum.io/rpc'),
    evm('optimism', 'https://sepolia.optimism.io'),
    evm('polygon', 'https://rpc-amoy.polygon.technology'),
    evm('bnb', 'https://bsc-testnet-rpc.publicnode.com'),
    evm('avalanche', 'https://api.avax-test.network/ext/bc/C/rpc'),
    // Keyed free tiers refuse getProgramAccounts (vault allowlist and requests):
    // that one goes to a public node, like eth_getLogs above. Not
    // api.devnet.solana.com: it blocks requests from Cloudflare.
    {
      prefix: '/sol/devnet', upstream: env.SOL_DEVNET_URL || 'https://api.devnet.solana.com', kind: 'jsonrpc', methods: SOLANA_METHODS,
      publicUpstream: env.SOL_DEVNET_SCAN_URL || 'https://solana-devnet.api.onfinality.io/public', publicMethods: ['getProgramAccounts'],
    },
    {
      prefix: '/tron/nile', upstream: 'https://nile.trongrid.io', kind: 'rest',
      header: env.TRONGRID_KEY ? ['TRON-PRO-API-KEY', env.TRONGRID_KEY] : undefined,
      // Exactly the HTTP API calls the app makes (src/tron), plus the
      // Ethereum-style JSON-RPC: nothing else spends the TronGrid key (A8-9).
      allow: (method, path) => (method === 'POST' && (TRON_PATHS.includes(path) || path === '/jsonrpc'))
        // Vault discovery reads the owner's outgoing history (src/tron createdContracts).
        || (method === 'GET' && TRON_HISTORY.test(path)),
      jsonrpcPath: '/jsonrpc', methods: EVM_METHODS,
    },
    {
      prefix: '/ton/testnet', upstream: 'https://testnet.toncenter.com', kind: 'rest',
      header: env.TONCENTER_KEY ? ['X-API-Key', env.TONCENTER_KEY] : undefined,
      allow: (method, path) => method === 'POST' && path === '/api/v2/jsonRPC' || method === 'GET' && /^\/api\/v3\/[A-Za-z/]+$/.test(path),
      jsonrpcPath: '/api/v2/jsonRPC', methods: TON_V2_METHODS,
    },
    esplora('/btc/signet', 'https://mempool.space/signet/api'),
    esplora('/ltc/testnet', 'https://litecoinspace.org/testnet/api'),
  ];
}

function esplora(prefix, upstream) {
  return {
    prefix, upstream, kind: 'rest',
    // Reads, plus broadcasting a transaction.
    allow: (method, path) => method === 'GET' && /^\/[A-Za-z0-9/_.:-]*$/.test(path) || method === 'POST' && path === '/tx',
  };
}

const json = (status, body) => new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json', 'Cache-Control': 'no-store', 'X-Content-Type-Options': 'nosniff' } });
const refuse = (status, message) => json(status, { error: message });

/** JSON-RPC body: only allowed methods, bounded batches. Returns an error message or null. */
export function checkJsonRpc(text, methods) {
  let body;
  try {
    body = JSON.parse(text);
  } catch {
    return 'body is not JSON';
  }
  const calls = Array.isArray(body) ? body : [body];
  if (calls.length === 0 || calls.length > MAX_BATCH) return `batches are limited to ${MAX_BATCH} calls`;
  for (const c of calls) {
    if (!c || typeof c !== 'object' || typeof c.method !== 'string' || !methods.includes(c.method)) {
      return `method not allowed: ${String(c?.method).slice(0, 64)}`;
    }
  }
  return null;
}

/** Handles one request. `fetchUpstream` is injected for tests. */
export async function handle(request, env = {}, fetchUpstream = fetch) {
  const url = new URL(request.url);
  if (url.pathname === '/health') return json(200, { ok: true });
  // Per-network status for status.avelock.app (cached, public facts only).
  if (url.pathname === '/status' && request.method === 'GET') return statusResponse(env, fetchUpstream);
  const route = routes(env).find(r => url.pathname === r.prefix || url.pathname.startsWith(r.prefix + '/'));
  if (!route) return refuse(404, 'unknown route');
  const rest = url.pathname.slice(route.prefix.length);
  const method = request.method;
  if (method !== 'GET' && method !== 'POST') return refuse(405, 'method not allowed');

  let body;
  if (method === 'POST') {
    const length = Number(request.headers.get('content-length') ?? 0);
    if (length > MAX_BODY) return refuse(413, 'body too large');
    body = await request.text();
    if (body.length > MAX_BODY) return refuse(413, 'body too large');
  }
  if (route.kind === 'jsonrpc') {
    if (method !== 'POST' || rest !== '') return refuse(405, 'JSON-RPC takes POST only');
    const bad = checkJsonRpc(body, route.methods);
    if (bad) return refuse(403, bad);
  } else {
    if (!route.allow(method, rest)) return refuse(403, 'path not allowed');
    if (method === 'POST' && route.jsonrpcPath === rest) {
      const bad = checkJsonRpc(body, route.methods);
      if (bad) return refuse(403, bad);
    }
  }

  // Methods the keyed provider does not serve go to the route's public node.
  const usesPublic = route.publicUpstream && route.publicMethods?.some(m => new RegExp(`"method"\\s*:\\s*"${m}"`).test(body ?? ''));
  const upstreamBase = usesPublic ? route.publicUpstream : route.upstream;
  const target = upstreamBase + rest + (route.kind === 'rest' && url.search ? url.search : '');
  const headers = { Accept: 'application/json' };
  if (method === 'POST') headers['Content-Type'] = request.headers.get('content-type') || 'application/json';
  if (route.header) headers[route.header[0]] = route.header[1];
  let upstream;
  try {
    upstream = await fetchUpstream(target, { method, headers, body, redirect: 'manual', signal: AbortSignal.timeout(UPSTREAM_TIMEOUT_MS) });
  } catch (e) {
    return e?.name === 'TimeoutError' ? refuse(504, 'upstream timed out') : refuse(502, 'upstream unreachable');
  }
  // Pass the answer through; drop the provider's headers (cookies, keys echoed back, etc.).
  const out = new Headers({ 'Content-Type': upstream.headers.get('content-type') || 'application/json', 'Cache-Control': 'no-store', 'X-Content-Type-Options': 'nosniff' });
  const retryAfter = upstream.headers.get('retry-after');
  if (retryAfter) out.set('Retry-After', retryAfter);
  return new Response(upstream.body, { status: upstream.status, headers: out });
}

/**
 * The key a per-IP limit counts against (A8-7): an IPv4 address, or the /64
 * of an IPv6 one — a client can switch freely inside its /64.
 */
export function limitKey(ip) {
  const a = String(ip || 'unknown');
  if (!a.includes(':')) return a;
  const [head] = a.split('::');
  const groups = a.includes('::') ? head.split(':').filter(Boolean) : a.split(':');
  while (groups.length < 4) groups.push('0');
  return groups.slice(0, 4).map(g => g.toLowerCase()).join(':') + '::/64';
}
