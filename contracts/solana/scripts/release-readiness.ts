import {createHash} from 'crypto';
import {readFileSync} from 'fs';
import {AccountInfo, Connection, PublicKey} from '@solana/web3.js';

export const UPGRADEABLE_LOADER = new PublicKey('BPFLoaderUpgradeab1e11111111111111111111111');
const PROGRAM_TAG = 2;
const PROGRAM_DATA_TAG = 3;
const PROGRAM_DATA_HEADER = 45;
export type Snapshot = {
  genesisHash: string;
  program: AccountInfo<Buffer> | null;
  programData: AccountInfo<Buffer> | null;
};
export function programDataAddress(programId: PublicKey): PublicKey {
  return PublicKey.findProgramAddressSync([programId.toBuffer()], UPGRADEABLE_LOADER)[0];
}

/** Read-only release gate for the v3 upgradeable loader. No transaction signer,
 * deploy, upgrade, authority mutation or permissive override is provided. */
export function verifyReleaseReadiness(
  programId: PublicKey,
  expectedGenesisHash: string,
  reviewedImage: Buffer,
  snapshot: Snapshot,
) {
  if (!expectedGenesisHash || snapshot.genesisHash !== expectedGenesisHash)
    throw new Error('Wrong or unspecified cluster genesis hash.');
  if (reviewedImage.length < 4 || !reviewedImage.subarray(0, 4).equals(Buffer.from([0x7f, 0x45, 0x4c, 0x46])))
    throw new Error('A reviewed ELF program image is required.');
  const program = snapshot.program;
  if (!program || !program.executable || program.lamports <= 0 || !program.owner.equals(UPGRADEABLE_LOADER))
    throw new Error('Program is absent, non-executable or owned by an unsupported loader.');
  if (program.data.length !== 36 || program.data.readUInt32LE(0) !== PROGRAM_TAG)
    throw new Error('Invalid loader Program state.');
  const expectedData = programDataAddress(programId);
  if (!new PublicKey(program.data.subarray(4, 36)).equals(expectedData))
    throw new Error('Wrong ProgramData binding.');
  const state = snapshot.programData;
  if (!state || state.executable || state.lamports <= 0 || !state.owner.equals(UPGRADEABLE_LOADER) ||
      state.data.length < PROGRAM_DATA_HEADER || state.data.readUInt32LE(0) !== PROGRAM_DATA_TAG)
    throw new Error('Invalid or missing ProgramData state.');
  // Bincode: enum:u32, deployment slot:u64, Option<Pubkey> tag:u8.
  if (state.data[12] !== 0)
    throw new Error('Upgrade authority is present or malformed; program is not release-ready.');
  const deployed = state.data.subarray(PROGRAM_DATA_HEADER);
  if (deployed.length < reviewedImage.length ||
      !deployed.subarray(0, reviewedImage.length).equals(reviewedImage) ||
      deployed.subarray(reviewedImage.length).some(byte => byte !== 0))
    throw new Error('Deployed bytecode does not match the reviewed image.');
  return {
    programId: programId.toBase58(),
    genesisHash: expectedGenesisHash,
    programData: expectedData.toBase58(),
    imageSha256: createHash('sha256').update(reviewedImage).digest('hex'),
    upgradeAuthority: null,
  };
}

/**
 * The same check through several independent RPCs (audit A6-H3): every
 * one must answer and pass, and all must see the same accounts. Returns
 * the release manifest to compile into the app (src/solana/release.ts).
 */
export function verifyAcrossRpcs(
  programId: PublicKey,
  expectedGenesisHash: string,
  reviewedImage: Buffer,
  snapshots: Snapshot[],
  minRpcs: number,
) {
  if (snapshots.length < minRpcs) throw new Error(`At least ${minRpcs} independent RPCs are required.`);
  const results = snapshots.map(s => verifyReleaseReadiness(programId, expectedGenesisHash, reviewedImage, s));
  const same = (s: Snapshot) => Buffer.concat([s.program!.data, s.programData!.data]);
  if (snapshots.some(s => !same(s).equals(same(snapshots[0])))) throw new Error('The RPCs disagree about the program accounts.');
  return {
    ...results[0],
    rpcs: snapshots.length,
    manifest: {
      cluster: expectedGenesisHash === '5eykt4UsFv8P8NJdTREpY1vzqKqZKvdpKuc147dw2N9d' ? 'mainnet-beta' : 'devnet',
      genesisHash: expectedGenesisHash,
      programId: programId.toBase58(),
      image: { sha256: results[0].imageSha256, length: reviewedImage.length },
    },
  };
}

async function main() {
  const args = process.argv.slice(2);
  if (args.length < 5)
    throw new Error('Usage: npm run check:release -- <PROGRAM_ID> <EXPECTED_GENESIS_HASH> <REVIEWED_SO_PATH> <RPC_URL> <RPC_URL> [<RPC_URL>...]  (mainnet: at least 3 RPCs from different operators)');
  const [program, genesis, imagePath, ...rpcs] = args;
  const programId = new PublicKey(program);
  const image = readFileSync(imagePath);
  const snapshots = await Promise.all(rpcs.map(async rpc => {
    const connection = new Connection(rpc, 'finalized');
    const genesisHash = await connection.getGenesisHash();
    // Both accounts are fetched in one snapshot, not across two independent slots.
    const accounts = await connection.getMultipleAccountsInfo([programId, programDataAddress(programId)], 'finalized');
    return { genesisHash, program: accounts[0], programData: accounts[1] };
  }));
  const minRpcs = genesis === '5eykt4UsFv8P8NJdTREpY1vzqKqZKvdpKuc147dw2N9d' ? 3 : 2;
  console.log(JSON.stringify(verifyAcrossRpcs(programId, genesis, image, snapshots, minRpcs), null, 2));
}
if (require.main === module) {
  main().catch(error => { console.error(error instanceof Error ? error.message : String(error)); process.exitCode = 1; });
}
