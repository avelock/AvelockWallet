import { test } from 'node:test';
import assert from 'node:assert/strict';
import { handle, limitKey, MAX_BATCH } from '../src/proxy.mjs';
import { nodeHandler } from '../src/node.mjs';
import { createServer, request as httpRequest } from 'node:http';

function upstream() {
  const calls = [];
  const fn = async (url, init) => {
    calls.push({ url, init });
    return new Response('{"result":1}', { status: 200, headers: { 'content-type': 'application/json', 'set-cookie': 'x=1', 'x-provider-key': 'secret' } });
  };
  return { calls, fn };
}
const post = (path, body, headers = {}) => new Request(`https://rpc.avelock.app${path}`, { method: 'POST', headers: { 'content-type': 'application/json', ...headers }, body: typeof body === 'string' ? body : JSON.stringify(body) });
const get = path => new Request(`https://rpc.avelock.app${path}`);

test('passes an allowed JSON-RPC call to the route upstream, without client headers', async () => {
  const u = upstream();
  const res = await handle(post('/evm/arbitrum', { jsonrpc: '2.0', id: 1, method: 'eth_call', params: [] }, { cookie: 'a', authorization: 'b' }), {}, u.fn);
  assert.equal(res.status, 200);
  assert.equal(u.calls[0].url, 'https://sepolia-rollup.arbitrum.io/rpc');
  assert.deepEqual(Object.keys(u.calls[0].init.headers).sort(), ['Accept', 'Content-Type']);
  assert.equal(res.headers.get('set-cookie'), null);
  assert.equal(res.headers.get('x-provider-key'), null);
});

test('refuses methods the app does not use, and large batches', async () => {
  const u = upstream();
  assert.equal((await handle(post('/sol/devnet', { method: 'requestAirdrop' }), {}, u.fn)).status, 403);
  assert.equal((await handle(post('/evm/eth', { method: 'debug_traceTransaction' }), {}, u.fn)).status, 403);
  const batch = Array.from({ length: MAX_BATCH + 1 }, (_, i) => ({ id: i, method: 'eth_blockNumber' }));
  assert.equal((await handle(post('/evm/eth', batch), {}, u.fn)).status, 403);
  assert.equal((await handle(post('/evm/eth', 'not json'), {}, u.fn)).status, 403);
  assert.equal(u.calls.length, 0);
});

test('adds the provider key held by the proxy, never sent by the app', async () => {
  const u = upstream();
  await handle(post('/ton/testnet/api/v2/jsonRPC', { method: 'runGetMethod' }, { 'x-api-key': 'client' }), { TONCENTER_KEY: 'k1' }, u.fn);
  assert.equal(u.calls[0].url, 'https://testnet.toncenter.com/api/v2/jsonRPC');
  assert.equal(u.calls[0].init.headers['X-API-Key'], 'k1');
  await handle(post('/tron/nile/wallet/triggersmartcontract', {}), { TRONGRID_KEY: 'k2' }, u.fn);
  assert.equal(u.calls[1].init.headers['TRON-PRO-API-KEY'], 'k2');
  await handle(post('/sol/devnet', { method: 'getBalance' }), { SOL_DEVNET_URL: 'https://devnet.provider.example/?api-key=k3' }, u.fn);
  assert.equal(u.calls[2].url, 'https://devnet.provider.example/?api-key=k3');
});

test('REST routes keep path and query, only allowed paths', async () => {
  const u = upstream();
  assert.equal((await handle(get('/ton/testnet/api/v3/nft/items?owner_address=abc&limit=5'), {}, u.fn)).status, 200);
  assert.equal(u.calls[0].url, 'https://testnet.toncenter.com/api/v3/nft/items?owner_address=abc&limit=5');
  assert.equal((await handle(get('/btc/signet/address/tb1qxyz/utxo'), {}, u.fn)).status, 200);
  assert.equal(u.calls[1].url, 'https://mempool.space/signet/api/address/tb1qxyz/utxo');
  assert.equal((await handle(post('/btc/signet/tx', '0200'), {}, u.fn)).status, 200);
  assert.equal((await handle(post('/btc/signet/address/x', '{}'), {}, u.fn)).status, 403);
  assert.equal((await handle(post('/tron/nile/wallet/../admin', '{}'), {}, u.fn)).status, 403);
  assert.equal((await handle(post('/ton/testnet/api/v2/jsonRPC', { method: 'anythingElse' }), {}, u.fn)).status, 403);
  assert.equal((await handle(get('/nope'), {}, u.fn)).status, 404);
});

test('caps the body size and reports an unreachable upstream', async () => {
  const u = upstream();
  const big = JSON.stringify({ method: 'eth_call', params: ['x'.repeat(200 * 1024)] });
  assert.equal((await handle(post('/evm/eth', big), {}, u.fn)).status, 413);
  const down = async () => { throw new Error('down'); };
  assert.equal((await handle(post('/evm/eth', { method: 'eth_blockNumber' }), {}, down)).status, 502);
});

test('Tron: only the paths the app calls, and nosniff on every answer (A8-9)', async () => {
  const u = upstream();
  assert.equal((await handle(post('/tron/nile/wallet/getnowblock', {}), {}, u.fn)).status, 403);
  const ok = await handle(post('/tron/nile/wallet/broadcasthex', {}), {}, u.fn);
  assert.equal(ok.status, 200);
  assert.equal(ok.headers.get('x-content-type-options'), 'nosniff');
  assert.equal((await handle(get('/tron/nile/v1/accounts/x'), {}, u.fn)).headers.get('x-content-type-options'), 'nosniff');
});

test('a provider that does not answer in time is a 504 (A8-6)', async () => {
  const slow = async () => { const e = new Error('timeout'); e.name = 'TimeoutError'; throw e; };
  assert.equal((await handle(post('/evm/eth', { method: 'eth_blockNumber' }), {}, slow)).status, 504);
});

test('IPv6 clients are counted per /64 (A8-7)', () => {
  assert.equal(limitKey('2001:db8:1:2:aaaa::1'), limitKey('2001:db8:1:2:bbbb::9'));
  assert.notEqual(limitKey('2001:db8:1:2::1'), limitKey('2001:db8:1:3::1'));
  assert.equal(limitKey('203.0.113.7'), '203.0.113.7');
});

test('the plain server answers bad requests instead of crashing (A8-6)', async () => {
  const server = createServer((req, res) => { void nodeHandler(req, res, {}); }).listen(0, '127.0.0.1');
  await new Promise(r => server.once('listening', r));
  const { port } = server.address();
  const call = (method, opts = {}) => new Promise(resolve => {
    const r = httpRequest({ host: '127.0.0.1', port, method, path: '/evm/eth', headers: { 'content-type': 'application/json', ...opts.headers } }, res => { res.resume(); resolve(res.statusCode); });
    r.on('error', () => resolve('aborted'));
    if (opts.abort) { r.write('{"method":'); setTimeout(() => r.destroy(), 20); } else r.end(opts.body);
  });
  assert.equal(await call('TRACE'), 400);
  await call('POST', { abort: true, headers: { 'content-length': '100' } });
  // Still alive after a broken upload:
  assert.equal(await call('PUT'), 400);
  server.close();
});

test('TRON account history is readable for one address only (vault discovery)', async () => {
  const u = upstream();
  const ok = await handle(get('/tron/nile/v1/accounts/TUuTZswyAsg9ZnQZ3aoWTZfNnLtAv4gmWZ/transactions?only_from=true&limit=200'), {}, u.fn);
  assert.equal(ok.status, 200);
  assert.ok(u.calls[0].url.startsWith('https://nile.trongrid.io/v1/accounts/TUuTZswyAsg9ZnQZ3aoWTZfNnLtAv4gmWZ/transactions?'));
  assert.equal((await handle(get('/tron/nile/v1/accounts/TUuTZswyAsg9ZnQZ3aoWTZfNnLtAv4gmWZ/transactions/trc20'), {}, u.fn)).status, 403);
  assert.equal((await handle(get('/tron/nile/v1/accounts/../admin/transactions'), {}, u.fn)).status, 403);
  assert.equal((await handle(post('/tron/nile/v1/accounts/TUuTZswyAsg9ZnQZ3aoWTZfNnLtAv4gmWZ/transactions', {}), {}, u.fn)).status, 403);
});

test('event scans go to the public node, other calls to the configured provider', async () => {
  const u = upstream();
  const env = { EVM_ETH_URL: 'https://paid.example/key' };
  await handle(post('/evm/eth', { jsonrpc: '2.0', id: 1, method: 'eth_getLogs', params: [{}] }), env, u.fn);
  await handle(post('/evm/eth', { jsonrpc: '2.0', id: 2, method: 'eth_call', params: [] }), env, u.fn);
  assert.equal(u.calls[0].url, 'https://ethereum-sepolia-rpc.publicnode.com');
  assert.equal(u.calls[1].url, 'https://paid.example/key');
});

test('Solana getProgramAccounts goes to the public devnet node, other methods to the keyed one', async () => {
  const seen = [];
  const fetchUp = async (url) => { seen.push(url); return new Response('{}', { status: 200 }); };
  const env = { SOL_DEVNET_URL: 'https://keyed.example/abc' };
  const call = m => handle(new Request('https://rpc.avelock.app/sol/devnet', { method: 'POST', body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: m, params: [] }), headers: { 'content-type': 'application/json' } }), env, fetchUp);
  await call('getProgramAccounts');
  await call('getBalance');
  assert.equal(seen[0], 'https://solana-devnet.api.onfinality.io/public');
  assert.equal(seen[1], 'https://keyed.example/abc');
});
