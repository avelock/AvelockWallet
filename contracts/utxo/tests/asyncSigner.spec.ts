// Async signing for a key held elsewhere (NATIVE_SIGNING_PLAN.md): the same
// messages and spends as the synchronous path, verified the same way.
import * as bip39 from 'bip39';
import { ownerKey } from '../src/mnemonicKeys';
import { litecoinTestnet } from '../src/networks';
import { signOperationAsync, signReadAsync, verifyOperation, verifyWithdrawalIntent } from '../src/signer/messages';

test('async signatures verify like the sync ones, intent included', async () => {
  const k = ownerKey(bip39.generateMnemonic(256), litecoinTestnet);
  const remote = { publicKey: k.publicKey, signSchnorr: async (h: Buffer) => k.signSchnorr(h) };
  const account = k.publicKey.toString('hex');
  const domain = { network: 'litecoin-testnet' as const, signer: '00'.repeat(32) };
  const op = await signOperationAsync({ domain, account, nonce: 4, expiresAt: 1, head: 'aa', operation: { op: 'requestWithdrawal', to: 'tltc1qxyz', amount: 5000 } as any }, remote);
  expect(verifyOperation(op)).toBe(true);
  const o = op.body.operation as any;
  expect(verifyWithdrawalIntent({ domain, account, nonce: 4, to: o.to, amount: o.amount }, o.intent)).toBe(true);
  expect(verifyOperation(await signReadAsync({ domain, account, expiresAt: 1, operation: { op: 'read' } }, remote))).toBe(true);
});
