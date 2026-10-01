import { test, beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import { handle } from '../src/proxy.mjs';
import { checkAll, NETWORKS, resetStatusCache, SLOW_MS, STATUS_TTL_MS, statusResponse } from '../src/status.mjs';

beforeEach(() => resetStatusCache());

/** An upstream that answers every probe like a healthy node. */
function healthy() {
  const calls = [];
  const fn = async (url, init) => {
    calls.push({ url, init });
    if (url.endsWith('/blocks/tip/height')) return new Response('812345', { status: 200 });
    const body = JSON.parse(init.body);
    const result = body.method === 'eth_blockNumber' ? '0x10' : body.method === 'getSlot' ? 3000 : { last: { seqno: 77 } };
    return new Response(JSON.stringify({ jsonrpc: '2.0', id: 1, result }), { status: 200, headers: { 'content-type': 'application/json' } });
  };
  return { calls, fn };
}

test('every network is probed once and reported up with its latest block', async () => {
  const u = healthy();
  const s = await checkAll({}, u.fn);
  assert.equal(s.networks.length, NETWORKS.length);
  assert.equal(u.calls.length, NETWORKS.length);
  for (const n of s.networks) {
    assert.equal(n.status, 'up', n.id);
    assert.ok(n.height > 0, n.id);
  }
  assert.equal(s.networks.find(n => n.id === 'ton').height, 77);
  assert.equal(s.networks.find(n => n.id === 'btc').height, 812345);
});

test('the answer never carries an upstream URL or a provider key', async () => {
  const u = healthy();
  const res = await handle(new Request('https://rpc.avelock.app/status'), { TONCENTER_KEY: 'secret-ton', TRONGRID_KEY: 'secret-tron', SOL_DEVNET_URL: 'https://sol.example/key-123' }, u.fn);
  assert.equal(res.status, 200);
  assert.equal(res.headers.get('access-control-allow-origin'), '*');
  const text = await res.text();
  for (const leak of ['secret-ton', 'secret-tron', 'key-123', 'http']) assert.ok(!text.includes(leak), leak);
  // The keys do reach the providers that need them.
  assert.equal(u.calls.find(c => c.url.includes('toncenter')).init.headers['X-API-Key'], 'secret-ton');
});

test('an error, a bad answer or no answer is "down"; a slow one is "degraded"', async () => {
  const fn = async (url, init) => {
    if (url.includes('sepolia.base.org')) return new Response('oops', { status: 500 });
    if (url.includes('arbitrum')) return new Response('{"result":"0x0"}', { status: 200 });
    if (url.includes('optimism')) throw new TypeError('network down');
    if (url.includes('polygon')) {
      await new Promise(r => setTimeout(r, SLOW_MS + 50));
      return new Response('{"result":"0x5"}', { status: 200 });
    }
    return healthy().fn(url, init);
  };
  const s = await checkAll({}, fn);
  const by = id => s.networks.find(n => n.id === id).status;
  assert.equal(by('base'), 'down');
  assert.equal(by('arbitrum'), 'down');
  assert.equal(by('optimism'), 'down');
  assert.equal(by('polygon'), 'degraded');
  assert.equal(by('eth'), 'up');
});

test('checks run at most once per cache period', async () => {
  const u = healthy();
  let t = 1_000_000;
  const now = () => t;
  const { statusResponse } = await import('../src/status.mjs');
  await statusResponse({}, u.fn, now);
  await statusResponse({}, u.fn, now);
  assert.equal(u.calls.length, NETWORKS.length);
  t += STATUS_TTL_MS;
  await statusResponse({}, u.fn, now);
  assert.equal(u.calls.length, 2 * NETWORKS.length);
});

test('only GET reads the status', async () => {
  const u = healthy();
  const res = await handle(new Request('https://rpc.avelock.app/status', { method: 'POST', body: '{}' }), {}, u.fn);
  assert.notEqual(res.status, 200);
  assert.equal(u.calls.length, 0);
});

test('requests that arrive together share one check (no probe storm)', async () => {
  resetStatusCache();
  let calls = 0;
  const upstream = async () => { calls++; await new Promise(r => setTimeout(r, 20)); return new Response('{"result":"0x10"}', { status: 200 }); };
  await Promise.all([1, 2, 3, 4, 5].map(() => statusResponse({}, upstream)));
  assert.equal(calls, NETWORKS.length);
});
