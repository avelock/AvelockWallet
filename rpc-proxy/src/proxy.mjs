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
      // Exactly the indexer calls the app makes (round2 M-4): NFTs, jettons,
      // history and delivery traces. Nothing else spends the TonCenter key.
      allow: (method, path) => method === 'POST' && path === '/api/v2/jsonRPC' || method === 'GET' && TON_V3_PATHS.includes(path),
      jsonrpcPath: '/api/v2/jsonRPC', methods: TON_V2_METHODS,
    },
    esplora('/btc/signet', 'https://mempool.space/signet/api'),
    esplora('/ltc/testnet', 'https://litecoinspace.org/testnet/api'),
  ];
}

function esplora(prefix, upstream) {
  return {
    prefix, upstream, kind: 'rest',
    // Exactly the reads the app makes, plus broadcasting (round2 M-4).
    allow: (method, path) => method === 'GET' && ESPLORA_GETS.some(r => r.test(path)) || method === 'POST' && path === '/tx',
  };
}

const TON_V3_PATHS = ['/api/v3/nft/items', '/api/v3/jetton/wallets', '/api/v3/transactions', '/api/v3/traces'];
const ADDR = '[A-Za-z0-9]{20,100}';
const ESPLORA_GETS = [
  new RegExp(`^/address/${ADDR}/(utxo|txs)$`),
  /^\/tx\/[0-9a-f]{64}\/status$/,
  /^\/blocks\/tip\/height$/,
  /^\/v1\/fees\/recommended$/,
];
/** Query parameters the app sends, per REST path; others are dropped (round2 M-4). */
const QUERY_KEYS = {
  '/api/v3/nft/items': ['owner_address', 'limit', 'offset', 'include_on_sale'],
  '/api/v3/jetton/wallets': ['owner_address', 'exclude_zero_balance', 'limit', 'offset'],
  '/api/v3/transactions': ['account', 'limit', 'offset', 'sort'],
  '/api/v3/traces': ['trace_id'],
};
const TRON_QUERY = ['only_from', 'only_to', 'limit', 'fingerprint', 'only_confirmed', 'order_by', 'min_timestamp'];
function cleanQuery(path, search) {
  if (!search) return '';
  const allowed = QUERY_KEYS[path] ?? (TRON_HISTORY.test(path) ? TRON_QUERY : []);
  const out = new URLSearchParams();
  for (const [k, v] of new URLSearchParams(search)) if (allowed.includes(k) && v.length <= 1000) out.append(k, v);
  const q = out.toString();
  return q ? `?${q}` : '';
}

const json = (status, body) => new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json', 'Cache-Control': 'no-store', 'X-Content-Type-Options': 'nosniff' } });
const refuse = (status, message) => json(status, { error: message });

/** JSON-RPC body: only allowed methods, bounded batches. Returns an error message or null. */
export function checkJsonRpc(text, methods) {
  return parseJsonRpc(text, methods).error;
}

/**
 * Checks a JSON-RPC body and rebuilds it from the parsed calls (round2 M-1):
 * only `jsonrpc`, `id`, `method` and `params` go upstream, so a node whose
 * parser reads duplicate or differently-cased keys sees exactly the method
 * checked here. `{ error }` or `{ body, calls }`.
 */
export function parseJsonRpc(text, methods) {
  let parsed;
  try {
    parsed = JSON.parse(text);
  } catch {
    return { error: 'body is not JSON' };
  }
  const batch = Array.isArray(parsed);
  const calls = batch ? parsed : [parsed];
  if (calls.length === 0 || calls.length > MAX_BATCH) return { error: `batches are limited to ${MAX_BATCH} calls` };
  const clean = [];
  for (const c of calls) {
    if (!c || typeof c !== 'object' || typeof c.method !== 'string' || !methods.includes(c.method)) {
      const shown = typeof c?.method === 'string' ? c.method.slice(0, 64) : typeof c?.method;
      return { error: `method not allowed: ${shown}` };
    }
    const id = c.id;
    if (id !== undefined && id !== null && typeof id !== 'string' && typeof id !== 'number') return { error: 'bad id' };
    if (c.params !== undefined && (c.params === null || typeof c.params !== 'object')) return { error: 'bad params' };
    clean.push({ jsonrpc: '2.0', ...(id !== undefined ? { id } : {}), method: c.method, ...(c.params !== undefined ? { params: c.params } : {}) });
  }
  return { body: JSON.stringify(batch ? clean : clean[0]), calls: clean };
}

/**
 * Calls the provider bills far above a plain read (round2 H-1): log and
 * history scans, proofs, traces, program scans.
 */
const HEAVY = new Set(['eth_getLogs', 'eth_getProof', 'eth_getBlockByNumber', 'getSignaturesForAddress', 'getProgramAccounts', 'getTransactions', 'getBlock', 'getTokenAccountsByOwner']);
export const HEAVY_WEIGHT = 10;
/** Sends: always served, even past the shared budget (the app must reach the chain). */
const SENDS = new Set(['eth_sendRawTransaction', 'sendTransaction', 'sendBoc', 'sendBocReturnHash']);

/** What one request costs: one per call, more for heavy calls (round2 H-1). */
export const callWeight = (calls, rest = '') => {
  if (!calls) return /\/(transactions|traces)\b/.test(rest) ? HEAVY_WEIGHT : 1;
  return Math.max(1, calls.reduce((n, c) => n + (HEAVY.has(c.method) ? HEAVY_WEIGHT : 1), 0));
};

/** A request that only sends transactions. */
export const isSend = (calls, method, rest) =>
  calls ? calls.length > 0 && calls.every(c => SENDS.has(c.method)) : method === 'POST' && /^\/(tx|wallet\/broadcasthex|api\/v2\/sendBoc(ReturnHash)?)$/.test(rest);

/** Largest answer passed on (round2 L-4), and how long its body may take (L-3). */
export const MAX_ANSWER = 8 * 1024 * 1024;
export const BODY_TIMEOUT_MS = 45000;

/** The JSON-RPC methods a (checked) body calls; none for other bodies. */
export function calledMethods(text) {
  try {
    const body = JSON.parse(text ?? '');
    return (Array.isArray(body) ? body : [body]).map(c => (c && typeof c.method === 'string' ? c.method : '')).filter(Boolean);
  } catch {
    return [];
  }
}

/** Handles one request. `fetchUpstream` is injected for tests. */
export async function handle(request, env = {}, fetchUpstream = fetch, charge = async () => true, shared = async () => true, waitUntil = undefined) {
  const url = new URL(request.url);
  if (url.pathname === '/health') return json(200, { ok: true });
  // Per-network status for status.avelock.app (cached, public facts only).
  if (url.pathname === '/status' && request.method === 'GET') return statusResponse(env, fetchUpstream, Date.now, waitUntil);
  // The app is not a browser (round2 M-3): a request a web page made from a
  // visitor's browser would spend that visitor's budget on our keys.
  const site = request.headers.get('sec-fetch-site');
  if (request.headers.get('origin') || (site && site !== 'none')) return refuse(403, 'browser requests are not served');
  const route = routes(env).find(r => url.pathname === r.prefix || url.pathname.startsWith(r.prefix + '/'));
  if (!route) return refuse(404, 'unknown route');
  const rest = url.pathname.slice(route.prefix.length);
  const method = request.method;
  if (method !== 'GET' && method !== 'POST') return refuse(405, 'method not allowed');

  let body;
  if (method === 'POST') {
    // Counted in bytes while reading (round2 L-9): no unbounded buffering, and
    // multi-byte characters can't slip past a character count.
    const declared = request.headers.get('content-length');
    if (declared !== null && !(Number(declared) <= MAX_BODY)) return refuse(413, 'body too large');
    const read = await readCapped(request.body, MAX_BODY);
    if (read === null) return refuse(413, 'body too large');
    body = read;
  }
  const isJsonRpc = route.kind === 'jsonrpc' || (method === 'POST' && route.jsonrpcPath === rest);
  let calls;
  if (route.kind === 'jsonrpc') {
    if (method !== 'POST' || rest !== '') return refuse(405, 'JSON-RPC takes POST only');
  } else if (!route.allow(method, rest)) {
    return refuse(403, 'path not allowed');
  }
  if (isJsonRpc) {
    const parsed = parseJsonRpc(body, route.methods);
    if (parsed.error) return refuse(403, parsed.error);
    body = parsed.body;
    calls = parsed.calls;
  }
  // A batch costs one unit per call, more for heavy ones (round2 H-1); the first unit was charged on arrival.
  const weight = callWeight(calls, rest);
  const limited = () => new Response(JSON.stringify({ error: 'rate limited' }), { status: 429, headers: { 'Content-Type': 'application/json', 'Retry-After': '60' } });
  if (weight > 1 && !(await charge(weight - 1))) return limited();
  // A budget shared by every client of a route (round2 H-1): many addresses
  // together cannot drain the provider. Sends always pass; the app goes
  // straight to public nodes on a 429.
  if (!isSend(calls, method, rest) && !(await shared(route.prefix, weight))) return limited();

  // Methods the keyed provider does not serve go to the route's public node.
  // Decided by the parsed calls, not by text in the body (MEGA_AUDIT ideas
  // crosscheck): a parameter value that merely contains such a method name
  // must not move the request to another upstream.
  const usesPublic = !!route.publicUpstream && !!route.publicMethods && (calls ?? []).some(c => route.publicMethods.includes(c.method));
  const upstreamBase = usesPublic ? route.publicUpstream : route.upstream;
  const target = upstreamBase + rest + (route.kind === 'rest' ? cleanQuery(rest, url.search) : '');
  const headers = { Accept: 'application/json' };
  // Our own content type, never the client's (round2 M-3).
  if (method === 'POST') headers['Content-Type'] = isJsonRpc ? 'application/json' : 'text/plain';
  if (route.header) headers[route.header[0]] = route.header[1];
  let upstream;
  // The header deadline does not cut the body (round2 L-3): the body has its own.
  const abort = new AbortController();
  let timedOut = false;
  let timer = setTimeout(() => { timedOut = true; abort.abort(); }, UPSTREAM_TIMEOUT_MS);
  try {
    upstream = await fetchUpstream(target, { method, headers, body, redirect: 'manual', signal: abort.signal });
  } catch (e) {
    clearTimeout(timer);
    return timedOut || e?.name === 'TimeoutError' ? refuse(504, 'upstream timed out') : refuse(502, 'upstream unreachable');
  }
  clearTimeout(timer);
  timer = setTimeout(() => { timedOut = true; abort.abort(); }, BODY_TIMEOUT_MS);
  // Pass the answer through; drop the provider's headers (cookies, keys echoed back, etc.).
  // Only JSON or plain text, never served as a page (round2 L-5).
  const type = upstream.headers.get('content-type') || 'application/json';
  const out = new Headers({
    'Content-Type': /^application\/json/i.test(type) ? type : 'text/plain; charset=utf-8',
    'Cache-Control': 'no-store', 'X-Content-Type-Options': 'nosniff',
    'Content-Security-Policy': "default-src 'none'; sandbox", 'Cross-Origin-Resource-Policy': 'same-site',
  });
  const retryAfter = upstream.headers.get('retry-after');
  if (retryAfter) out.set('Retry-After', retryAfter);
  // An error or redirect page that repeats a key is never passed on (round2 L-10).
  // The whole answer is read here, within its deadline and size (round2 L-3,
  // L-4): a slow or huge answer is a clean 504/502, never a cut-off 200.
  let text;
  try {
    text = await readCapped(upstream.body, MAX_ANSWER);
  } catch {
    text = undefined;
  } finally {
    clearTimeout(timer);
  }
  if (text === undefined) return timedOut ? refuse(504, 'upstream timed out') : refuse(502, 'upstream answer broken');
  if (text === null) return refuse(502, 'upstream answer too large');
  if (upstream.status < 200 || upstream.status >= 300) {
    const secrets = secretsOf(env);
    if (secrets.some(x => text.includes(x))) return refuse(upstream.status >= 400 ? upstream.status : 502, 'upstream error');
  }
  return new Response(text, { status: upstream.status, headers: out });
}

/** Key values and keyed URLs this proxy holds, for the error-page check. */
function secretsOf(env) {
  const out = [];
  for (const [k, v] of Object.entries(env)) {
    if (typeof v !== 'string' || v.length < 8) continue;
    if (/_KEY$/.test(k)) out.push(v);
    if (/_URL$/.test(k)) {
      try {
        const u = new URL(v);
        if (u.pathname.length > 8) out.push(u.pathname);
        if (u.search.length > 8) out.push(u.search.slice(1));
      } catch { /* not a URL */ }
    }
  }
  return out;
}

/** The body as text, or null when it is larger than `max` bytes. */
async function readCapped(stream, max) {
  if (!stream) return '';
  const reader = stream.getReader();
  const parts = [];
  let size = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    size += value.byteLength;
    if (size > max) {
      await reader.cancel().catch(() => {});
      return null;
    }
    parts.push(value);
  }
  const all = new Uint8Array(size);
  let at = 0;
  for (const p of parts) { all.set(p, at); at += p.byteLength; }
  return new TextDecoder().decode(all);
}

/**
 * The key a per-IP limit counts against (A8-7): an IPv4 address, or the /64
 * of an IPv6 one — a client can switch freely inside its /64.
 */
export function limitKey(ip) {
  const a = String(ip || '').trim();
  // IPv4, or IPv4 written as IPv6 (round2 L-1): its own key, not a shared /64.
  const v4 = a.match(/^(?:::ffff:)?(\d{1,3}(?:\.\d{1,3}){3})$/i);
  if (v4) return v4[1].split('.').every(x => Number(x) <= 255) ? v4[1] : 'unknown';
  if (!/^[0-9a-f:]+$/i.test(a) || !a.includes(':')) return 'unknown';
  const halves = a.split('::');
  if (halves.length > 2) return 'unknown';
  const head = halves[0] ? halves[0].split(':') : [];
  const tail = halves.length === 2 && halves[1] ? halves[1].split(':') : [];
  const fill = halves.length === 2 ? 8 - head.length - tail.length : 0;
  const groups = [...head, ...Array(Math.max(0, fill)).fill('0'), ...tail];
  if (groups.length !== 8 || groups.some(g => !/^[0-9a-f]{1,4}$/i.test(g))) return 'unknown';
  return groups.slice(0, 4).map(g => parseInt(g, 16).toString(16)).join(':') + '::/64';
}
