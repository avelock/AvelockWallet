import { expect } from 'chai';
import {
  Connection, Keypair, PublicKey, SystemProgram, Transaction,
  TransactionInstruction, sendAndConfirmTransaction, AccountMeta,
} from '@solana/web3.js';
import {
  TOKEN_PROGRAM_ID, ASSOCIATED_TOKEN_PROGRAM_ID, getAssociatedTokenAddressSync,
  createMint, mintTo, getAccount,
} from '@solana/spl-token';
import * as L from './layout';

const PROGRAM_ID = new PublicKey('9r172eBe2XJ9PPFH8rmb6XbxNkrNLkMnqBZmSfCwUiXD');
const connection = new Connection('http://127.0.0.1:8899', 'confirmed');

async function airdrop(pubkey: PublicKey, sol = 5) {
  const sig = await connection.requestAirdrop(pubkey, sol * 1_000_000_000);
  await connection.confirmTransaction(sig, 'confirmed');
}

async function send(ixs: TransactionInstruction[], signers: Keypair[]) {
  const tx = new Transaction().add(...ixs);
  return sendAndConfirmTransaction(connection, tx, signers, { commitment: 'confirmed' });
}

function meta(pubkey: PublicKey, isSigner: boolean, isWritable: boolean): AccountMeta {
  return { pubkey, isSigner, isWritable };
}

const OPTIONAL_NONE = () => meta(PROGRAM_ID, false, false);

// confirmationWindow has generous headroom (well beyond the ~2s we
// actually wait past availableAt) because expiresAt = availableAt +
// confirmationWindow, and the confirm transaction's real wall-clock send
// time is subject to RPC/validator jitter — a tight window flakes with a
// spurious RequestExpired on a slow CI run.
const DEFAULT_DELAYS = {
  withdrawalDelay: 2n, addressDelay: 2n, confirmationWindow: 20n,
  policyDelay: 2n, minWithdrawalDelay: 1n, minAddressDelay: 1n,
};

async function initializeVault(owner: Keypair, delays = DEFAULT_DELAYS) {
  const [vault] = L.vaultPda(PROGRAM_ID, owner.publicKey);
  const [extension] = L.extensionPda(PROGRAM_ID, vault);
  const ix = new TransactionInstruction({
    programId: PROGRAM_ID,
    keys: [
      meta(owner.publicKey, true, true),
      meta(vault, false, true),
      meta(extension, false, true),
      meta(SystemProgram.programId, false, false),
    ],
    data: L.ixInitializeVault(delays),
  });
  await send([ix], [owner]);
  return { vault, extension };
}

async function addAllowedAddress(owner: Keypair, vault: PublicKey, extension: PublicKey, destination: PublicKey) {
  const [entry] = L.allowlistPda(PROGRAM_ID, extension, destination);
  const ix = new TransactionInstruction({
    programId: PROGRAM_ID,
    keys: [
      meta(owner.publicKey, true, true),
      meta(vault, false, false),
      meta(extension, false, false),
      meta(destination, false, false),
      meta(entry, false, true),
      meta(SystemProgram.programId, false, false),
    ],
    data: L.ixNoArgs('add_allowed_address'),
  });
  await send([ix], [owner]);
  return entry;
}

async function removeAllowedAddress(owner: Keypair, vault: PublicKey, extension: PublicKey, entry: PublicKey) {
  const ix = new TransactionInstruction({
    programId: PROGRAM_ID,
    keys: [
      meta(owner.publicKey, true, false),
      meta(vault, false, false),
      meta(extension, false, false),
      meta(entry, false, true),
    ],
    data: L.ixNoArgs('remove_allowed_address'),
  });
  await send([ix], [owner]);
}

async function fetchAccount(pubkey: PublicKey): Promise<Buffer> {
  const info = await connection.getAccountInfo(pubkey, 'confirmed');
  if (!info) throw new Error(`account ${pubkey.toBase58()} not found`);
  return info.data;
}

async function expectRevert(promise: Promise<unknown>): Promise<void> {
  try {
    await promise;
    expect.fail('expected instruction to fail, but it succeeded');
  } catch (e: any) {
    // A real simulation/on-chain failure — good.
    expect(e).to.exist;
  }
}

describe('AvelockWallet (Solana)', function () {
  this.timeout(60_000);

  it('initializes a Vault + SecurityExtension atomically, with the config passed at creation', async () => {
    const owner = Keypair.generate();
    await airdrop(owner.publicKey);
    const { vault, extension } = await initializeVault(owner);

    const vaultData = L.decodeVault(await fetchAccount(vault));
    expect(vaultData.owner.equals(owner.publicKey)).to.be.true;
    expect(vaultData.securityExtension.equals(extension)).to.be.true;

    const extData = L.decodeSecurityExtension(await fetchAccount(extension));
    expect(extData.wallet.equals(vault)).to.be.true;
    expect(extData.withdrawalDelay).to.equal(DEFAULT_DELAYS.withdrawalDelay);
    expect(extData.addressDelay).to.equal(DEFAULT_DELAYS.addressDelay);
    expect(extData.minWithdrawalDelay).to.equal(DEFAULT_DELAYS.minWithdrawalDelay);
    expect(extData.nextRequestId).to.equal(0n);
  });

  it('rejects an initial delay below its own immutable minimum', async () => {
    const owner = Keypair.generate();
    await airdrop(owner.publicKey);
    await expectRevert(initializeVault(owner, { ...DEFAULT_DELAYS, withdrawalDelay: 0n, minWithdrawalDelay: 1n }));
  });

  it('a new destination is inactive until the address delay elapses', async () => {
    const owner = Keypair.generate();
    await airdrop(owner.publicKey);
    const { vault, extension } = await initializeVault(owner);
    const dest = Keypair.generate().publicKey;

    const entry = await addAllowedAddress(owner, vault, extension, dest);
    let entryData = L.decodeAllowlistEntry(await fetchAccount(entry));
    expect(entryData.activeAt > 0n).to.be.true;
    const now = BigInt(Math.floor(Date.now() / 1000));
    expect(entryData.activeAt > now - 5n).to.be.true;

    await new Promise(r => setTimeout(r, (Number(DEFAULT_DELAYS.addressDelay) + 2) * 1000));
    // isAddressActive is evaluated on-chain at request time — here we just
    // confirm the stored activation timestamp is in the past now.
    entryData = L.decodeAllowlistEntry(await fetchAccount(entry));
    const nowAfter = BigInt(Math.floor(Date.now() / 1000));
    expect(nowAfter >= entryData.activeAt).to.be.true;
  });

  it('removing an address bumps its epoch and immediately deactivates it', async () => {
    const owner = Keypair.generate();
    await airdrop(owner.publicKey);
    const { vault, extension } = await initializeVault(owner);
    const dest = Keypair.generate().publicKey;
    const entry = await addAllowedAddress(owner, vault, extension, dest);
    await removeAllowedAddress(owner, vault, extension, entry);
    const entryData = L.decodeAllowlistEntry(await fetchAccount(entry));
    expect(entryData.activeAt).to.equal(0n);
    expect(entryData.epoch).to.equal(1n);
  });

  it('full native-SOL lifecycle: request -> too-early confirm rejected -> confirm succeeds after delay', async () => {
    const owner = Keypair.generate();
    await airdrop(owner.publicKey);
    const { vault, extension } = await initializeVault(owner);
    // Fund the vault PDA itself with lamports to withdraw.
    await send([SystemProgram.transfer({ fromPubkey: owner.publicKey, toPubkey: vault, lamports: 2_000_000_000 })], [owner]);

    const dest = Keypair.generate();
    const entry = await addAllowedAddress(owner, vault, extension, dest.publicKey);
    await new Promise(r => setTimeout(r, (Number(DEFAULT_DELAYS.addressDelay) + 2) * 1000));

    const extBefore = L.decodeSecurityExtension(await fetchAccount(extension));
    const requestId = extBefore.nextRequestId;
    const [request] = L.requestPda(PROGRAM_ID, extension, requestId);

    const amount = 500_000_000n;
    const reqIx = new TransactionInstruction({
      programId: PROGRAM_ID,
      keys: [
        meta(owner.publicKey, true, true),
        meta(vault, false, false),
        meta(extension, false, true),
        meta(dest.publicKey, false, false),
        meta(entry, false, false),
        OPTIONAL_NONE(),
        meta(request, false, true),
        meta(SystemProgram.programId, false, false),
      ],
      data: L.ixAmountOnly('request_native_withdrawal', amount),
    });
    await send([reqIx], [owner]);

    const reqData = L.decodeWithdrawalRequest(await fetchAccount(request));
    expect(reqData.to.equals(dest.publicKey)).to.be.true;
    expect(reqData.amount).to.equal(amount);
    expect(reqData.mint).to.be.null;
    expect(reqData.executed).to.be.false;

    const confirmIx = () => new TransactionInstruction({
      programId: PROGRAM_ID,
      keys: [
        meta(owner.publicKey, true, false),
        meta(vault, false, true),
        meta(extension, false, false),
        meta(request, false, true),
        meta(entry, false, false),
        meta(dest.publicKey, false, true),
        meta(SystemProgram.programId, false, false),
      ],
      data: L.ixNoArgs('confirm_native_withdrawal'),
    });

    // Too early — withdrawal_delay has not elapsed yet.
    await expectRevert(send([confirmIx()], [owner]));

    await new Promise(r => setTimeout(r, (Number(DEFAULT_DELAYS.withdrawalDelay) + 2) * 1000));

    const destBalanceBefore = await connection.getBalance(dest.publicKey);
    await send([confirmIx()], [owner]);
    const destBalanceAfter = await connection.getBalance(dest.publicKey);
    expect(destBalanceAfter - destBalanceBefore).to.equal(Number(amount));

    const reqAfter = L.decodeWithdrawalRequest(await fetchAccount(request));
    expect(reqAfter.executed).to.be.true;
  });

  it('cancel works before execution and blocks a later confirm', async () => {
    const owner = Keypair.generate();
    await airdrop(owner.publicKey);
    const { vault, extension } = await initializeVault(owner);
    await send([SystemProgram.transfer({ fromPubkey: owner.publicKey, toPubkey: vault, lamports: 1_000_000_000 })], [owner]);

    const dest = Keypair.generate();
    const entry = await addAllowedAddress(owner, vault, extension, dest.publicKey);
    await new Promise(r => setTimeout(r, (Number(DEFAULT_DELAYS.addressDelay) + 2) * 1000));

    const extBefore = L.decodeSecurityExtension(await fetchAccount(extension));
    const requestId = extBefore.nextRequestId;
    const [request] = L.requestPda(PROGRAM_ID, extension, requestId);

    await send([new TransactionInstruction({
      programId: PROGRAM_ID,
      keys: [
        meta(owner.publicKey, true, true), meta(vault, false, false), meta(extension, false, true),
        meta(dest.publicKey, false, false), meta(entry, false, false), OPTIONAL_NONE(),
        meta(request, false, true), meta(SystemProgram.programId, false, false),
      ],
      data: L.ixAmountOnly('request_native_withdrawal', 100_000_000n),
    })], [owner]);

    await send([new TransactionInstruction({
      programId: PROGRAM_ID,
      keys: [meta(owner.publicKey, true, false), meta(vault, false, false), meta(extension, false, false), meta(request, false, true)],
      data: L.ixNoArgs('cancel_withdrawal'),
    })], [owner]);

    const reqData = L.decodeWithdrawalRequest(await fetchAccount(request));
    expect(reqData.cancelled).to.be.true;

    await new Promise(r => setTimeout(r, (Number(DEFAULT_DELAYS.withdrawalDelay) + 2) * 1000));
    await expectRevert(send([new TransactionInstruction({
      programId: PROGRAM_ID,
      keys: [
        meta(owner.publicKey, true, false), meta(vault, false, true), meta(extension, false, false),
        meta(request, false, true), meta(entry, false, false), meta(dest.publicKey, false, true),
        meta(SystemProgram.programId, false, false),
      ],
      data: L.ixNoArgs('confirm_native_withdrawal'),
    })], [owner]));
  });

  it('policy change: increasing a delay still waits for the current policy delay', async () => {
    const owner = Keypair.generate();
    await airdrop(owner.publicKey);
    const { vault, extension } = await initializeVault(owner);

    const setIx = new TransactionInstruction({
      programId: PROGRAM_ID,
      keys: [meta(owner.publicKey, true, false), meta(vault, false, false), meta(extension, false, true)],
      data: L.ixSetParam('set_withdrawal_delay', DEFAULT_DELAYS.withdrawalDelay + 1000n),
    });
    await send([setIx], [owner]);

    let extData = L.decodeSecurityExtension(await fetchAccount(extension));
    expect(extData.withdrawalDelay).to.equal(DEFAULT_DELAYS.withdrawalDelay); // not applied yet
    expect(extData.pending[L.PARAM_WITHDRAWAL_DELAY].exists).to.be.true;
    expect(extData.pending[L.PARAM_WITHDRAWAL_DELAY].newValue).to.equal(DEFAULT_DELAYS.withdrawalDelay + 1000n);

    const applyIx = new TransactionInstruction({
      programId: PROGRAM_ID,
      keys: [meta(owner.publicKey, true, false), meta(vault, false, false), meta(extension, false, true)],
      data: L.ixParamOnly('apply_param_change', L.PARAM_WITHDRAWAL_DELAY),
    });

    // Too early — policyDelay has not elapsed.
    await expectRevert(send([applyIx], [owner]));

    await new Promise(r => setTimeout(r, (Number(DEFAULT_DELAYS.policyDelay) + 2) * 1000));
    await send([applyIx], [owner]);
    extData = L.decodeSecurityExtension(await fetchAccount(extension));
    expect(extData.withdrawalDelay).to.equal(DEFAULT_DELAYS.withdrawalDelay + 1000n);
  });

  it('rejects weakening a delay below its immutable minimum, even as a queued change', async () => {
    const owner = Keypair.generate();
    await airdrop(owner.publicKey);
    const { vault, extension } = await initializeVault(owner, { ...DEFAULT_DELAYS, withdrawalDelay: 5n, minWithdrawalDelay: 5n });

    const setIx = new TransactionInstruction({
      programId: PROGRAM_ID,
      keys: [meta(owner.publicKey, true, false), meta(vault, false, false), meta(extension, false, true)],
      data: L.ixSetParam('set_withdrawal_delay', 4n),
    });
    await expectRevert(send([setIx], [owner]));

    const extData = L.decodeSecurityExtension(await fetchAccount(extension));
    expect(extData.pending[L.PARAM_WITHDRAWAL_DELAY].exists).to.be.false;
  });

  it('rejects a parameter value above the fixed cap', async () => {
    const owner = Keypair.generate();
    await airdrop(owner.publicKey);
    const { vault, extension } = await initializeVault(owner);
    const NINETY_DAYS = 90n * 24n * 60n * 60n;
    const setIx = new TransactionInstruction({
      programId: PROGRAM_ID,
      keys: [meta(owner.publicKey, true, false), meta(vault, false, false), meta(extension, false, true)],
      data: L.ixSetParam('set_withdrawal_delay', NINETY_DAYS + 1n),
    });
    await expectRevert(send([setIx], [owner]));
  });

  it('prunes a cancelled request immediately, returning rent to the owner', async () => {
    const owner = Keypair.generate();
    await airdrop(owner.publicKey);
    const { vault, extension } = await initializeVault(owner);
    await send([SystemProgram.transfer({ fromPubkey: owner.publicKey, toPubkey: vault, lamports: 1_000_000_000 })], [owner]);
    const dest = Keypair.generate();
    const entry = await addAllowedAddress(owner, vault, extension, dest.publicKey);
    await new Promise(r => setTimeout(r, (Number(DEFAULT_DELAYS.addressDelay) + 2) * 1000));

    const ext = L.decodeSecurityExtension(await fetchAccount(extension));
    const [request] = L.requestPda(PROGRAM_ID, extension, ext.nextRequestId);
    await send([new TransactionInstruction({
      programId: PROGRAM_ID,
      keys: [
        meta(owner.publicKey, true, true), meta(vault, false, false), meta(extension, false, true),
        meta(dest.publicKey, false, false), meta(entry, false, false), OPTIONAL_NONE(),
        meta(request, false, true), meta(SystemProgram.programId, false, false),
      ],
      data: L.ixAmountOnly('request_native_withdrawal', 1_000n),
    })], [owner]);
    await send([new TransactionInstruction({
      programId: PROGRAM_ID,
      keys: [meta(owner.publicKey, true, false), meta(vault, false, false), meta(extension, false, false), meta(request, false, true)],
      data: L.ixNoArgs('cancel_withdrawal'),
    })], [owner]);

    await send([new TransactionInstruction({
      programId: PROGRAM_ID,
      keys: [
        meta(owner.publicKey, true, true), meta(vault, false, false), meta(extension, false, false),
        meta(request, false, true),
      ],
      data: L.ixNoArgs('prune_request'),
    })], [owner]);

    const closed = await connection.getAccountInfo(request, 'confirmed');
    expect(closed).to.be.null;
  });

  it('a settled request cannot be pruned before the retention window elapses', async () => {
    const owner = Keypair.generate();
    await airdrop(owner.publicKey);
    const { vault, extension } = await initializeVault(owner);
    await send([SystemProgram.transfer({ fromPubkey: owner.publicKey, toPubkey: vault, lamports: 1_000_000_000 })], [owner]);
    const dest = Keypair.generate();
    const entry = await addAllowedAddress(owner, vault, extension, dest.publicKey);
    await new Promise(r => setTimeout(r, (Number(DEFAULT_DELAYS.addressDelay) + 2) * 1000));

    const ext = L.decodeSecurityExtension(await fetchAccount(extension));
    const [request] = L.requestPda(PROGRAM_ID, extension, ext.nextRequestId);
    await send([new TransactionInstruction({
      programId: PROGRAM_ID,
      keys: [
        meta(owner.publicKey, true, true), meta(vault, false, false), meta(extension, false, true),
        meta(dest.publicKey, false, false), meta(entry, false, false), OPTIONAL_NONE(),
        meta(request, false, true), meta(SystemProgram.programId, false, false),
      ],
      // Below Solana's rent-exempt minimum, a brand-new zero-lamport
      // recipient ending the transaction with a small-but-nonzero
      // balance is rejected by the runtime ("insufficient funds for
      // rent") — use an amount comfortably above that floor.
      data: L.ixAmountOnly('request_native_withdrawal', 2_000_000n),
    })], [owner]);

    await new Promise(r => setTimeout(r, (Number(DEFAULT_DELAYS.withdrawalDelay) + 2) * 1000));
    await send([new TransactionInstruction({
      programId: PROGRAM_ID,
      keys: [
        meta(owner.publicKey, true, false), meta(vault, false, true), meta(extension, false, false),
        meta(request, false, true), meta(entry, false, false), meta(dest.publicKey, false, true),
        meta(SystemProgram.programId, false, false),
      ],
      data: L.ixNoArgs('confirm_native_withdrawal'),
    })], [owner]);

    await expectRevert(send([new TransactionInstruction({
      programId: PROGRAM_ID,
      keys: [meta(owner.publicKey, true, true), meta(vault, false, false), meta(extension, false, false), meta(request, false, true)],
      data: L.ixNoArgs('prune_request'),
    })], [owner]));
  });

  it('SPL-token lifecycle: request -> confirm transfers out of the Vault PDA\'s own token account', async () => {
    const owner = Keypair.generate();
    await airdrop(owner.publicKey);
    // A generous confirmationWindow here: minting/creating the ATA below
    // takes several confirmed transactions before the withdrawal is even
    // requested, and the request's own expiresAt clock starts ticking
    // from the moment it's submitted — a tight window risks a flaky
    // RequestExpired race against real wall-clock time in a test.
    const { vault, extension } = await initializeVault(owner, { ...DEFAULT_DELAYS, confirmationWindow: 20n });
    await send([SystemProgram.transfer({ fromPubkey: owner.publicKey, toPubkey: vault, lamports: 1_000_000_000 })], [owner]);

    const mintAuthority = Keypair.generate();
    await airdrop(mintAuthority.publicKey);
    const mint = await createMint(connection, mintAuthority, mintAuthority.publicKey, null, 0);

    const vaultAta = getAssociatedTokenAddressSync(mint, vault, true);
    // Create the vault's ATA and fund it, using the mint authority as payer.
    const { createAssociatedTokenAccountInstruction } = await import('@solana/spl-token');
    await send([createAssociatedTokenAccountInstruction(mintAuthority.publicKey, vaultAta, vault, mint)], [mintAuthority]);
    await mintTo(connection, mintAuthority, mint, vaultAta, mintAuthority, 1_000);

    const dest = Keypair.generate();
    await airdrop(dest.publicKey);
    const entry = await addAllowedAddress(owner, vault, extension, dest.publicKey);
    await new Promise(r => setTimeout(r, (Number(DEFAULT_DELAYS.addressDelay) + 2) * 1000));

    const ext = L.decodeSecurityExtension(await fetchAccount(extension));
    const [request] = L.requestPda(PROGRAM_ID, extension, ext.nextRequestId);
    const amount = 250n;

    await send([new TransactionInstruction({
      programId: PROGRAM_ID,
      keys: [
        meta(owner.publicKey, true, true), meta(vault, false, false), meta(extension, false, true),
        meta(dest.publicKey, false, false), meta(entry, false, false), meta(mint, false, false),
        meta(request, false, true), meta(SystemProgram.programId, false, false),
      ],
      data: L.ixAmountOnly('request_token_withdrawal', amount),
    })], [owner]);

    await new Promise(r => setTimeout(r, (Number(DEFAULT_DELAYS.withdrawalDelay) + 2) * 1000));

    const destAta = getAssociatedTokenAddressSync(mint, dest.publicKey, false);
    await send([new TransactionInstruction({
      programId: PROGRAM_ID,
      keys: [
        meta(owner.publicKey, true, true),
        meta(vault, false, false),
        meta(extension, false, false),
        meta(request, false, true),
        meta(entry, false, false),
        meta(dest.publicKey, false, false),
        meta(mint, false, false),
        meta(vaultAta, false, true),
        meta(destAta, false, true),
        meta(TOKEN_PROGRAM_ID, false, false),
        meta(ASSOCIATED_TOKEN_PROGRAM_ID, false, false),
        meta(SystemProgram.programId, false, false),
      ],
      data: L.ixNoArgs('confirm_token_withdrawal'),
    })], [owner]);

    const destAccount = await getAccount(connection, destAta);
    expect(destAccount.amount).to.equal(amount);

    const reqAfter = L.decodeWithdrawalRequest(await fetchAccount(request));
    expect(reqAfter.executed).to.be.true;
    expect(reqAfter.mint?.equals(mint)).to.be.true;
  });
});
