// The vault's internal key is BIP-341's H, recomputed here from G itself
// (MEGA_AUDIT btc_01 F3): nobody picked it, so nobody knows its discrete log.
import { createHash } from 'crypto';
import { NUMS_INTERNAL_KEY } from '../src/vault';

test('NUMS key = SHA256 of the uncompressed generator', () => {
  const G = Buffer.from('04'
    + '79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798'
    + '483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8', 'hex');
  expect(createHash('sha256').update(G).digest()).toEqual(NUMS_INTERNAL_KEY);
});
