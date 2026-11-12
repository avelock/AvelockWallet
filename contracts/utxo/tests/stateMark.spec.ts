import * as bip39 from 'bip39';
import { existsSync, mkdirSync, mkdtempSync, renameSync, readdirSync, readFileSync, rmSync, unlinkSync, writeFileSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';
import { ownerAccountXpub, ownerKey } from '../src/mnemonicKeys';
import { litecoinTestnet } from '../src/networks';
import { signOperation } from '../src/signer/messages';
import { createSignerServer } from '../src/signer/server';

// round2 bitcoin_signer L-6: a state restored from a backup is refused.
describe('state high-water mark', () => {
  it('refuses to start on a state.json older than the last saved one', () => {
    const dir = mkdtempSync(join(tmpdir(), 'avelock-mark-'));
    const clock = 1_800_000_000;
    const opts = { dataDir: dir, network: litecoinTestnet, networkName: 'litecoin-testnet' as const, now: () => clock };
    try {
      const { signer } = createSignerServer(opts);
      const register = () => {
        const mnemonic = bip39.generateMnemonic(256);
        const owner = ownerKey(mnemonic, litecoinTestnet);
        const identity = owner.publicKey.toString('hex');
        signer.submit(signOperation({ domain: signer.domain, account: identity, nonce: 0, expiresAt: clock + 600, operation: {
          op: 'register', accountXpub: ownerAccountXpub(mnemonic, litecoinTestnet),
          vault: { generation: 0, owner: identity, signers: [signer.publicKey], threshold: 1, reserveBlocks: 57_600 },
          policy: { withdrawalDelay: 86400, addressDelay: 86400, policyDelay: 86400, confirmationWindow: 86400, maxFee: 100_000 },
          floors: { withdrawalDelay: 3600, addressDelay: 3600 },
        } }, owner));
      };
      register();
      const first = readdirSync(join(dir, 'accounts'));
      register();
      expect(() => createSignerServer(opts)).not.toThrow();
      // A backup from before the second account: its file is gone again.
      const second = readdirSync(join(dir, 'accounts')).find(f => !first.includes(f))!;
      unlinkSync(join(dir, 'accounts', second));
      expect(() => createSignerServer(opts)).toThrow(/older than the last saved state/);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
});

test('one file per account; an old single state.json is split up once (round2 M-4)', () => {
  const dir = mkdtempSync(join(tmpdir(), 'avelock-split-'));
  const clock = 1_800_000_000;
  const opts = { dataDir: dir, network: litecoinTestnet, networkName: 'litecoin-testnet' as const, now: () => clock };
  try {
    const { signer } = createSignerServer(opts);
    const mnemonic = bip39.generateMnemonic(256);
    const owner = ownerKey(mnemonic, litecoinTestnet);
    const identity = owner.publicKey.toString('hex');
    signer.submit(signOperation({ domain: signer.domain, account: identity, nonce: 0, expiresAt: clock + 600, operation: {
      op: 'register', accountXpub: ownerAccountXpub(mnemonic, litecoinTestnet),
      vault: { generation: 0, owner: identity, signers: [signer.publicKey], threshold: 1, reserveBlocks: 57_600 },
      policy: { withdrawalDelay: 86400, addressDelay: 86400, policyDelay: 86400, confirmationWindow: 86400, maxFee: 100_000 },
      floors: { withdrawalDelay: 3600, addressDelay: 3600 },
    } }, owner));
    const file = join(dir, 'accounts', `${identity}.json`);
    expect(existsSync(file)).toBe(true);
    // Back to the old layout: everything in one state.json.
    const account = JSON.parse(readFileSync(file, 'utf8'));
    rmSync(join(dir, 'accounts'), { recursive: true });
    writeFileSync(join(dir, 'state.json'), JSON.stringify({ accounts: { [identity]: account } }));
    const again = createSignerServer(opts).signer;
    expect(again.getAccount(identity)?.head).toEqual(account.head);
    expect(existsSync(file)).toBe(true);
    expect(existsSync(join(dir, 'state.json.migrated'))).toBe(true);
    // A split cut short leaves only the side directory: the next start splits again (REVIEW_last3days).
    rmSync(join(dir, 'accounts'), { recursive: true });
    renameSync(join(dir, 'state.json.migrated'), join(dir, 'state.json'));
    mkdirSync(join(dir, 'accounts.tmp'));
    writeFileSync(join(dir, 'accounts.tmp', 'partial'), 'x');
    const third = createSignerServer(opts).signer;
    expect(third.getAccount(identity)?.head).toEqual(account.head);
    expect(existsSync(join(dir, 'accounts.tmp'))).toBe(false);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('a first start in a data directory that does not exist yet makes it (signer key included)', () => {
  const { loadOrCreateKey } = require('../src/signer/server');
  const fresh = join(mkdtempSync(join(tmpdir(), 'signer-')), 'new', 'dir');
  expect(loadOrCreateKey(fresh).publicKey.length).toBe(32);
  expect(existsSync(join(fresh, 'signer.key'))).toBe(true);
});
