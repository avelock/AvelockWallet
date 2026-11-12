// MEGA_AUDIT btc_02 F1: co-signing requests are owner-signed.
// mobile_12 MB-1: every reply is signed by the signer, bound to its request.
import * as bip39 from 'bip39';
import { mkdtempSync, rmSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';
import { AddressInfo } from 'net';
import { ownerAccountXpub, ownerKey } from '../src/mnemonicKeys';
import { litecoinTestnet } from '../src/networks';
import { psbtDigest, signCosign, signOperation, signRead, verifyReply } from '../src/signer/messages';
import { createSignerServer } from '../src/signer/server';

test('replies are signed for their request; co-signing needs the owner signature over that PSBT', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'avelock-reply-'));
  const clock = 1_800_000_000;
  const { server, signer } = createSignerServer({ dataDir: dir, network: litecoinTestnet, networkName: 'litecoin-testnet', now: () => clock });
  await new Promise<void>(r => server.listen(0, '127.0.0.1', r));
  const base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
  const post = async (path: string, body: unknown) => {
    const res = await fetch(base + path, { method: 'POST', body: JSON.stringify(body) });
    return { status: res.status, body: await res.json() as any };
  };
  const mnemonic = bip39.generateMnemonic(256);
  const owner = ownerKey(mnemonic, litecoinTestnet);
  const account = owner.publicKey.toString('hex');
  try {
    const reg = signOperation({ domain: signer.domain, account, nonce: 0, expiresAt: clock + 600, operation: {
      op: 'register', accountXpub: ownerAccountXpub(mnemonic, litecoinTestnet),
      vault: { generation: 0, owner: account, signers: [signer.publicKey], threshold: 1, reserveBlocks: 57_600 },
      policy: { withdrawalDelay: 86400, addressDelay: 86400, policyDelay: 86400, confirmationWindow: 86400, maxFee: 100_000 },
      floors: { withdrawalDelay: 3600, addressDelay: 3600 },
    } }, owner);
    const r1 = await post('/op', reg);
    expect(r1.status).toBe(200);
    expect(verifyReply(signer.publicKey, reg.signature, r1.body)).toBe(true);

    const read = signRead({ domain: signer.domain, account, expiresAt: clock + 60, operation: { op: 'read' } }, owner);
    const r2 = await post('/account', read);
    expect(verifyReply(signer.publicKey, read.signature, r2.body)).toBe(true);
    // Bound to its request: the same reply does not verify for another one.
    expect(verifyReply(signer.publicKey, reg.signature, r2.body)).toBe(false);
    // A changed reply does not verify.
    expect(verifyReply(signer.publicKey, read.signature, { ...r2.body, nonce: 99 })).toBe(false);

    // The old bearer form (account + head) is refused.
    const bare = await post('/sign/refresh', { account, head: r2.body.head.hash, psbt: 'cHNidP8=' });
    expect(bare.body.error).toBe('bad_signature');
    // Signed for another PSBT: refused before anything is parsed.
    const req = signCosign({ domain: signer.domain, account, expiresAt: clock + 60, operation: { op: 'cosignRefresh', head: r2.body.head.hash, psbt: psbtDigest('other') } }, owner);
    const wrong = await post('/sign/refresh', { request: req, psbt: 'cHNidP8=' });
    expect(wrong.body.message).toMatch(/differs from the one signed for/);
  } finally {
    server.close();
    rmSync(dir, { recursive: true, force: true });
  }
});
