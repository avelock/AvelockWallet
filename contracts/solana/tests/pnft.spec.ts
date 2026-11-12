// Programmable NFTs (Metaplex pNFT) leave the vault through Token Metadata
// (round2 M-2, option 3). Needs Token Metadata on the local validator:
//   solana program dump -u devnet metaqbxxUerdq28cj1RbAWkYQm3ybzjb6a8bt518x1s token_metadata.so
//   solana-test-validator --reset --bpf-program metaqbxxUerdq28cj1RbAWkYQm3ybzjb6a8bt518x1s token_metadata.so \
//     --bpf-program 9r172eBe2XJ9PPFH8rmb6XbxNkrNLkMnqBZmSfCwUiXD target/deploy/avelock_wallet.so
//   PNFT=1 npx ts-mocha -p ./tsconfig.json -t 300000 tests/pnft.spec.ts
import { expect } from 'chai';
import {
  AccountMeta, Connection, Keypair, PublicKey, SystemProgram, SYSVAR_INSTRUCTIONS_PUBKEY, Transaction,
  TransactionInstruction, sendAndConfirmTransaction,
} from '@solana/web3.js';
import { ASSOCIATED_TOKEN_PROGRAM_ID, TOKEN_PROGRAM_ID, getAccount, getAssociatedTokenAddressSync } from '@solana/spl-token';
import { createUmi } from '@metaplex-foundation/umi-bundle-defaults';
import { generateSigner, keypairIdentity, percentAmount, publicKey as umiKey } from '@metaplex-foundation/umi';
import { fromWeb3JsKeypair } from '@metaplex-foundation/umi-web3js-adapters';
import { createProgrammableNft, mplTokenMetadata } from '@metaplex-foundation/mpl-token-metadata';
import * as L from './layout';

const PROGRAM_ID = new PublicKey('9r172eBe2XJ9PPFH8rmb6XbxNkrNLkMnqBZmSfCwUiXD');
const TM = new PublicKey('metaqbxxUerdq28cj1RbAWkYQm3ybzjb6a8bt518x1s');
const RPC = 'http://127.0.0.1:8899';
const connection = new Connection(RPC, 'confirmed');
const DELAYS = { withdrawalDelay: 2n, addressDelay: 2n, confirmationWindow: 60n, policyDelay: 2n, minWithdrawalDelay: 1n, minAddressDelay: 1n };
const meta = (pubkey: PublicKey, isSigner: boolean, isWritable: boolean): AccountMeta => ({ pubkey, isSigner, isWritable });
const ix = (keys: AccountMeta[], data: Buffer) => new TransactionInstruction({ programId: PROGRAM_ID, keys, data });
const sleep = (s: number) => new Promise(r => setTimeout(r, s * 1000));
const send = (ixs: TransactionInstruction[], signers: Keypair[]) =>
  sendAndConfirmTransaction(connection, new Transaction().add(...ixs), signers, { commitment: 'confirmed' });
async function airdrop(k: PublicKey, sol = 5) { await connection.confirmTransaction(await connection.requestAirdrop(k, sol * 1e9), 'confirmed'); }
const tmPda = (...seeds: Buffer[]) => PublicKey.findProgramAddressSync([Buffer.from('metadata'), TM.toBuffer(), ...seeds], TM)[0];

const run = process.env.PNFT ? describe : describe.skip;

run('Programmable NFTs (Solana, localnet with Token Metadata)', function () {
  this.timeout(300_000);

  it('a pNFT held by the vault is withdrawn after the delay, through Token Metadata', async () => {
    const owner = Keypair.generate();
    await airdrop(owner.publicKey);
    const [vault] = L.vaultPda(PROGRAM_ID, owner.publicKey);
    const [extension] = L.extensionPda(PROGRAM_ID, vault);
    await send([ix([meta(owner.publicKey, true, true), meta(vault, false, true), meta(extension, false, true), meta(SystemProgram.programId, false, false)], L.ixInitializeVault(DELAYS))], [owner]);

    // A pNFT minted straight into the vault PDA.
    const creator = Keypair.generate();
    await airdrop(creator.publicKey);
    const umi = createUmi(RPC, { commitment: 'confirmed' }).use(mplTokenMetadata()).use(keypairIdentity(fromWeb3JsKeypair(creator)));
    const mintSigner = generateSigner(umi);
    await createProgrammableNft(umi, {
      mint: mintSigner, name: 'Avelock test', uri: 'https://example.com/a.json',
      sellerFeeBasisPoints: percentAmount(0), tokenOwner: umiKey(vault.toBase58()),
    }).sendAndConfirm(umi, { confirm: { commitment: 'confirmed' } });
    const mint = new PublicKey(mintSigner.publicKey);
    const source = getAssociatedTokenAddressSync(mint, vault, true);
    const held = await getAccount(connection, source);
    expect(held.amount).to.equal(1n);
    expect(held.isFrozen, 'a pNFT token account is frozen').to.be.true;

    const dest = Keypair.generate();
    await airdrop(dest.publicKey, 1);
    const [entry] = L.allowlistPda(PROGRAM_ID, extension, dest.publicKey);
    await send([ix([meta(owner.publicKey, true, true), meta(vault, false, false), meta(extension, false, false), meta(dest.publicKey, false, false), meta(entry, false, true), meta(SystemProgram.programId, false, false)], L.ixNoArgs('add_allowed_address'))], [owner]);
    await sleep(3);
    const [request] = L.requestPda(PROGRAM_ID, extension, L.decodeSecurityExtension((await connection.getAccountInfo(extension))!.data).nextRequestId);
    await send([ix([
      meta(owner.publicKey, true, true), meta(vault, false, false), meta(extension, false, true),
      meta(dest.publicKey, false, false), meta(entry, false, false), meta(mint, false, false),
      meta(request, false, true), meta(SystemProgram.programId, false, false),
    ], L.ixAmountOnly('request_token_withdrawal', 1n))], [owner]);

    const destination = getAssociatedTokenAddressSync(mint, dest.publicKey);
    const confirm = (destRecord = tmPda(mint.toBuffer(), Buffer.from('token_record'), destination.toBuffer())) => ix([
      meta(owner.publicKey, true, true), meta(vault, false, false), meta(extension, false, false),
      meta(request, false, true), meta(entry, false, false), meta(dest.publicKey, false, false),
      meta(mint, false, false), meta(source, false, true), meta(destination, false, true),
      meta(tmPda(mint.toBuffer()), false, true), meta(tmPda(mint.toBuffer(), Buffer.from('edition')), false, false),
      meta(tmPda(mint.toBuffer(), Buffer.from('token_record'), source.toBuffer()), false, true), meta(destRecord, false, true),
      meta(SYSVAR_INSTRUCTIONS_PUBKEY, false, false), meta(TM, false, false),
      meta(TOKEN_PROGRAM_ID, false, false), meta(ASSOCIATED_TOKEN_PROGRAM_ID, false, false), meta(SystemProgram.programId, false, false),
      meta(PROGRAM_ID, false, false), meta(PROGRAM_ID, false, false), // no rule set
    ], L.ixNoArgs('confirm_pnft_withdrawal'));

    let early = false;
    try { await send([confirm()], [owner]); early = true; } catch { /* the delay is not over */ }
    expect(early, 'confirmed before the delay').to.be.false;
    await sleep(3);
    // A wrong token record is refused by this program before Token Metadata runs.
    let wrong = false;
    try { await send([confirm(Keypair.generate().publicKey)], [owner]); wrong = true; } catch { /* refused */ }
    expect(wrong, 'a substituted account was accepted').to.be.false;

    await send([confirm()], [owner]);
    expect((await getAccount(connection, destination)).amount).to.equal(1n);
    expect((await getAccount(connection, source)).amount).to.equal(0n);
    expect(L.decodeWithdrawalRequest((await connection.getAccountInfo(request))!.data).executed).to.be.true;
  });
});
