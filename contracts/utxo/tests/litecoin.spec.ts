import * as bitcoin from 'bitcoinjs-lib';
import * as bip39 from 'bip39';
import { mkdtempSync, rmSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';
import { AddressInfo } from 'net';
import { createVault } from '../src/vault';
import { ownerPath, ownerPublicKey } from '../src/keys';
import { ownerAccountXpub, ownerKey } from '../src/mnemonicKeys';
import { coinType, litecoin, litecoinTestnet } from '../src/networks';
import { signOperation } from '../src/signer/messages';
import { createSignerServer } from '../src/signer/server';

describe('Litecoin', () => {
  const mnemonic = bip39.generateMnemonic(256);

  it('uses coin type 2, so keys differ from Bitcoin test keys of the same seed', () => {
    expect(coinType(litecoinTestnet)).toBe(2);
    expect(coinType(litecoin)).toBe(2);
    expect(coinType(bitcoin.networks.testnet)).toBe(1);
    expect(ownerPath(litecoinTestnet, 3)).toBe("m/86'/2'/100'/0/3");
    expect(ownerKey(mnemonic, litecoinTestnet).publicKey.equals(ownerKey(mnemonic, bitcoin.networks.testnet).publicKey)).toBe(false);
    const xpub = ownerAccountXpub(mnemonic, litecoinTestnet);
    expect(ownerPublicKey(xpub, litecoinTestnet, 2).equals(ownerKey(mnemonic, litecoinTestnet, 2).publicKey)).toBe(true);
  });

  it('builds Taproot vault addresses with Litecoin prefixes', () => {
    const owner = ownerKey(mnemonic, litecoinTestnet).publicKey;
    const signer = ownerKey(bip39.generateMnemonic(), litecoinTestnet).publicKey;
    const test = createVault({ owner, signers: [signer], threshold: 1, reserveBlocks: 57_600, network: litecoinTestnet });
    const main = createVault({ owner, signers: [signer], threshold: 1, reserveBlocks: 57_600, network: litecoin });
    expect(test.address).toMatch(/^tltc1p/);
    expect(main.address).toMatch(/^ltc1p/);
    expect(test.output.equals(main.output)).toBe(true);
  });

  it('runs a signer on litecoin-testnet that refuses Bitcoin-domain operations', async () => {
    const dir = mkdtempSync(join(tmpdir(), 'avelock-ltc-'));
    const clock = 1_800_000_000;
    const { server, signer } = createSignerServer({ dataDir: dir, network: litecoinTestnet, networkName: 'litecoin-testnet', now: () => clock });
    await new Promise<void>(r => server.listen(0, '127.0.0.1', r));
    const base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
    const post = async (body: unknown) => {
      const res = await fetch(base + '/op', { method: 'POST', body: JSON.stringify(body) });
      return { status: res.status, body: await res.json() as any };
    };
    const owner = ownerKey(mnemonic, litecoinTestnet);
    const identity = owner.publicKey.toString('hex');
    const operation = {
      op: 'register' as const, accountXpub: ownerAccountXpub(mnemonic, litecoinTestnet),
      vault: { generation: 0, owner: identity, signers: [signer.publicKey], threshold: 1, reserveBlocks: 57_600 },
      policy: { withdrawalDelay: 86400, addressDelay: 86400, policyDelay: 86400, confirmationWindow: 86400, maxFee: 100_000 },
      floors: { withdrawalDelay: 3600, addressDelay: 3600 },
    };
    try {
      const wrong = await post(signOperation({ domain: { network: 'signet', signer: signer.publicKey }, account: identity, nonce: 0, expiresAt: clock + 600, operation }, owner));
      expect(wrong.body.error).toBe('wrong_domain');
      const ok = await post(signOperation({ domain: { network: 'litecoin-testnet', signer: signer.publicKey }, account: identity, nonce: 0, expiresAt: clock + 600, operation }, owner));
      expect(ok.status).toBe(200);
      expect(ok.body.address).toMatch(/^tltc1p/);
    } finally {
      server.close();
      rmSync(dir, { recursive: true, force: true });
    }
  });
});
