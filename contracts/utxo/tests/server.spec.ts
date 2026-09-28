import * as bitcoin from 'bitcoinjs-lib';
import * as bip39 from 'bip39';
import { mkdtempSync, rmSync, statSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';
import { AddressInfo } from 'net';
import { ownerAccountXpub, ownerKey } from '../src/mnemonicKeys';
import { signOperation, signRead } from '../src/signer/messages';
import { createSignerServer } from '../src/signer/server';

const network = bitcoin.networks.regtest;

describe('signer server', () => {
  const dir = mkdtempSync(join(tmpdir(), 'avelock-signer-'));
  const mnemonic = bip39.generateMnemonic(256);
  const owner = ownerKey(mnemonic, network);
  const identity = owner.publicKey.toString('hex');
  const clock = 1_800_000_000;
  afterAll(() => rmSync(dir, { recursive: true, force: true }));

  async function start() {
    const { server, signer } = createSignerServer({ dataDir: dir, network, networkName: 'regtest', now: () => clock });
    await new Promise<void>(r => server.listen(0, '127.0.0.1', r));
    const base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
    const call = async (path: string, body?: unknown) => {
      const res = await fetch(base + path, body === undefined ? {} : { method: 'POST', body: JSON.stringify(body) });
      return { status: res.status, body: await res.json() as any };
    };
    return { server, signer, call };
  }

  it('registers over HTTP, persists state and keeps the same key across restarts', async () => {
    const first = await start();
    const info = await first.call('/info');
    expect(info.body).toEqual({ publicKey: first.signer.publicKey, network: 'regtest' });
    const register = signOperation({
      domain: { network: 'regtest', signer: first.signer.publicKey }, account: identity, nonce: 0, expiresAt: clock + 600,
      operation: {
        op: 'register', accountXpub: ownerAccountXpub(mnemonic, network),
        vault: { generation: 0, owner: identity, signers: [first.signer.publicKey], threshold: 1, reserveBlocks: 100 },
        policy: { withdrawalDelay: 86400, addressDelay: 86400, policyDelay: 86400, confirmationWindow: 86400, maxFee: 5000 },
        floors: { withdrawalDelay: 3600, addressDelay: 3600 },
      },
    }, owner);
    const reg = await first.call('/op', register);
    expect(reg.status).toBe(200);
    expect(reg.body.address).toMatch(/^bcrt1p/);
    // Replay is rejected with a machine-readable code.
    expect((await first.call('/op', register)).body.error).toBe('exists');
    expect((await first.call('/op', { nonsense: true })).status).toBe(400);
    first.server.close();

    const second = await start();
    expect(second.signer.publicKey).toBe(first.signer.publicKey);
    // Account state is private: only an owner-signed read returns it.
    const read = signRead({ domain: { network: 'regtest', signer: second.signer.publicKey }, account: identity, expiresAt: clock + 60, operation: { op: 'read' } }, owner);
    const account = await second.call('/account', read);
    expect(account.body.nonce).toBe(1);
    expect(account.body.head).toEqual(reg.body.head);
    const forged = { ...read, signature: '00'.repeat(64) };
    expect((await second.call('/account', forged)).body.error).toBe('bad_signature');
    expect((await second.call(`/account/${identity}`)).status).toBe(404);
    expect(account.body.generations[0].address).toBe(reg.body.address);
    second.server.close();

    expect(statSync(join(dir, 'signer.key')).mode & 0o077).toBe(0);
  });
});

// Audit A15-5: behind the reverse proxy the limit counts the real client.
import { clientAddress } from '../src/signer/server';
test('the registration limit uses the address the local proxy forwarded', () => {
  const req = (peer: string, xff?: string) => ({ socket: { remoteAddress: peer }, headers: xff ? { 'x-forwarded-for': xff } : {} }) as any;
  expect(clientAddress(req('127.0.0.1', '203.0.113.9'))).toBe('203.0.113.9');
  // A client-set header is kept first; the proxy appends the real peer last.
  expect(clientAddress(req('127.0.0.1', '1.1.1.1, 203.0.113.9'))).toBe('203.0.113.9');
  // A header from a non-local peer is ignored.
  expect(clientAddress(req('198.51.100.7', '203.0.113.9'))).toBe('198.51.100.7');
  expect(clientAddress(req('127.0.0.1', 'garbage'))).toBe('127.0.0.1');
  expect(clientAddress(req('127.0.0.1', '203.0.113.9'), false)).toBe('127.0.0.1');
});

// Audit A15-6: IPv6 forms that carry a private IPv4 address.
import { isPrivateAddress } from '../src/signer/service';
test('IPv6 forms with a private IPv4 inside count as private', () => {
  for (const ip of ['::ffff:127.0.0.1', '::ffff:7f00:1', '::ffff:a00:1', '::127.0.0.1', '::ffff:0:192.168.1.1',
    '64:ff9b::a9fe:a9fe', '64:ff9b::10.0.0.1', '64:ff9b:1::c0a8:101', '2002:7f00:1::', '2002:c0a8:0101::1',
    '::1', '::', 'fc00::1', 'fe80::1', 'ff02::1', '2001:db8::1']) expect([ip, isPrivateAddress(ip)]).toEqual([ip, true]);
  for (const ip of ['2606:4700:4700::1111', '::ffff:8.8.8.8', '64:ff9b::808:808', '2002:808:808::1', '8.8.8.8'])
    expect([ip, isPrivateAddress(ip)]).toEqual([ip, false]);
});
