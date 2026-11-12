// Localnet tests for guards, Panic Lock and the round-2 checks (round2 L-5):
// these account contexts had only struct-level unit tests before.
import { expect } from 'chai';
import {
  Connection, Keypair, PublicKey, SystemProgram, Transaction,
  TransactionInstruction, sendAndConfirmTransaction, AccountMeta,
} from '@solana/web3.js';
import * as L from './layout';

const PROGRAM_ID = new PublicKey('9r172eBe2XJ9PPFH8rmb6XbxNkrNLkMnqBZmSfCwUiXD');
const connection = new Connection('http://127.0.0.1:8899', 'confirmed');
const DELAYS = {
  withdrawalDelay: 2n, addressDelay: 2n, confirmationWindow: 30n,
  policyDelay: 2n, minWithdrawalDelay: 1n, minAddressDelay: 1n,
};
const sleep = (s: number) => new Promise(r => setTimeout(r, s * 1000));
const meta = (pubkey: PublicKey, isSigner: boolean, isWritable: boolean): AccountMeta => ({ pubkey, isSigner, isWritable });
const ix = (keys: AccountMeta[], data: Buffer) => new TransactionInstruction({ programId: PROGRAM_ID, keys, data });
const keyArg = (name: string, key: PublicKey) => Buffer.concat([L.ixDiscriminator(name), key.toBuffer()]);

async function airdrop(pubkey: PublicKey, sol = 5) {
  const sig = await connection.requestAirdrop(pubkey, sol * 1_000_000_000);
  await connection.confirmTransaction(sig, 'confirmed');
}
async function send(ixs: TransactionInstruction[], signers: Keypair[]) {
  return sendAndConfirmTransaction(connection, new Transaction().add(...ixs), signers, { commitment: 'confirmed' });
}
async function fails(p: Promise<unknown>) {
  let ok = false;
  try { await p; ok = true; } catch { /* expected */ }
  expect(ok, 'expected the transaction to fail').to.be.false;
}
async function ext(extension: PublicKey) {
  return L.decodeSecurityExtension((await connection.getAccountInfo(extension, 'confirmed'))!.data);
}

/** A vault with lock_delay lowered to 2 s, so unlock can be tested. */
async function setup() {
  const owner = Keypair.generate();
  await airdrop(owner.publicKey);
  const [vault] = L.vaultPda(PROGRAM_ID, owner.publicKey);
  const [extension] = L.extensionPda(PROGRAM_ID, vault);
  await send([ix([meta(owner.publicKey, true, true), meta(vault, false, true), meta(extension, false, true), meta(SystemProgram.programId, false, false)], L.ixInitializeVault(DELAYS))], [owner]);
  await send([SystemProgram.transfer({ fromPubkey: owner.publicKey, toPubkey: vault, lamports: 1_000_000_000 })], [owner]);
  const ownerOnly = (data: Buffer) => send([ix([meta(owner.publicKey, true, false), meta(vault, false, false), meta(extension, false, true)], data)], [owner]);
  await ownerOnly(L.ixSetParam('set_lock_delay', 2n));
  await sleep(3);
  await ownerOnly(L.ixParamOnly('apply_param_change', L.PARAM_LOCK_DELAY));
  const guardAction = (guard: Keypair, data: Buffer, v = vault, e = extension) =>
    send([ix([meta(guard.publicKey, true, false), meta(v, false, false), meta(e, false, true)], data)], [guard]);
  const addAddress = async (dest: PublicKey) => {
    const [entry] = L.allowlistPda(PROGRAM_ID, extension, dest);
    await send([ix([meta(owner.publicKey, true, true), meta(vault, false, false), meta(extension, false, false), meta(dest, false, false), meta(entry, false, true), meta(SystemProgram.programId, false, false)], L.ixNoArgs('add_allowed_address'))], [owner]);
    return entry;
  };
  const request = async (dest: PublicKey, entry: PublicKey, amount = 100_000_000n) => {
    const [req] = L.requestPda(PROGRAM_ID, extension, (await ext(extension)).nextRequestId);
    await send([ix([meta(owner.publicKey, true, true), meta(vault, false, false), meta(extension, false, true), meta(dest, false, false), meta(entry, false, false), meta(PROGRAM_ID, false, false), meta(req, false, true), meta(SystemProgram.programId, false, false)], L.ixAmountOnly('request_native_withdrawal', amount))], [owner]);
    return req;
  };
  const confirm = (req: PublicKey, dest: PublicKey, entry: PublicKey) =>
    send([ix([meta(owner.publicKey, true, false), meta(vault, false, true), meta(extension, false, false), meta(req, false, true), meta(entry, false, false), meta(dest, false, true), meta(SystemProgram.programId, false, false)], L.ixNoArgs('confirm_native_withdrawal'))], [owner]);
  const seal = (entry: PublicKey) => send([ix([meta(extension, false, false), meta(entry, false, true)], L.ixNoArgs('seal_allowed_address'))], [owner]);
  return { owner, vault, extension, ownerOnly, guardAction, addAddress, request, confirm, seal };
}

describe('Guards and Panic Lock (Solana, localnet)', function () {
  this.timeout(120_000);

  it('a guard waits the address delay, then locks; the lock voids an older request; only the owner unlocks, after the delay', async () => {
    const v = await setup();
    const guard = Keypair.generate();
    const stranger = Keypair.generate();
    await airdrop(guard.publicKey, 1);
    await airdrop(stranger.publicKey, 1);
    const dest = Keypair.generate().publicKey;
    const entry = await v.addAddress(dest);
    await v.ownerOnly(keyArg('add_guard', guard.publicKey));
    await fails(v.guardAction(guard, L.ixNoArgs('guard_lock'))); // still waiting
    await sleep(3);
    await fails(v.guardAction(stranger, L.ixNoArgs('guard_lock')));
    const req = await v.request(dest, entry);
    await v.guardAction(guard, L.ixNoArgs('guard_lock'));
    expect((await ext(v.extension)).locked).to.be.true;
    await fails(v.request(dest, entry));
    await fails(v.ownerOnly(L.ixNoArgs('unlock'))); // lock delay not over
    await fails(v.guardAction(guard, L.ixNoArgs('unlock'))); // not the owner's context
    await sleep(3);
    await v.ownerOnly(L.ixNoArgs('unlock'));
    expect((await ext(v.extension)).locked).to.be.false;
    await fails(v.confirm(req, dest, entry)); // annulled by the lock
  });

  it("a guard of one vault cannot act on another", async () => {
    const a = await setup();
    const b = await setup();
    const guard = Keypair.generate();
    await airdrop(guard.publicKey, 1);
    await a.ownerOnly(keyArg('add_guard', guard.publicKey));
    await sleep(3);
    await fails(a.guardAction(guard, L.ixNoArgs('guard_lock'), b.vault, b.extension));
    await fails(a.guardAction(guard, L.ixNoArgs('guard_lock'), a.vault, b.extension));
    expect((await ext(b.extension)).locked).to.be.false;
  });

  it('a sealed destination survives five lock cycles; an unsealed one is voided (round2 L-4)', async () => {
    const v = await setup();
    const sealedDest = Keypair.generate().publicKey;
    const plainDest = Keypair.generate().publicKey;
    const sealedEntry = await v.addAddress(sealedDest);
    const plainEntry = await v.addAddress(plainDest);
    await fails(v.seal(sealedEntry)); // not active yet
    await sleep(3);
    await v.seal(sealedEntry);
    for (let i = 0; i < 5; i++) {
      await v.ownerOnly(L.ixNoArgs('lock'));
      await sleep(3);
      await v.ownerOnly(L.ixNoArgs('unlock'));
    }
    await v.request(sealedDest, sealedEntry);
    await fails(v.request(plainDest, plainEntry));
  });

  it('SOL is never sent to an account of this program (round2 L-7)', async () => {
    const v = await setup();
    // A program-owned destination: this vault's own extension account.
    const entry = await v.addAddress(v.extension);
    await sleep(3);
    const req = await v.request(v.extension, entry);
    await sleep(3);
    await fails(v.confirm(req, v.extension, entry));
  });
});
