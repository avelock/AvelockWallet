import {expect} from 'chai';
import {PublicKey} from '@solana/web3.js';
import {programDataAddress, Snapshot, UPGRADEABLE_LOADER, verifyAcrossRpcs, verifyReleaseReadiness} from '../../scripts/release-readiness';

const programId = new PublicKey(Buffer.alloc(32, 7));
// Synthetic fixture, never deployed or executed.
const image = Buffer.from([0x7f, 0x45, 0x4c, 0x46, 1, 2, 3]);
function snapshot(): Snapshot {
  const program = Buffer.alloc(36);
  program.writeUInt32LE(2); programDataAddress(programId).toBuffer().copy(program, 4);
  const data = Buffer.alloc(45 + image.length + 16);
  data.writeUInt32LE(3); data.writeBigUInt64LE(123n, 4); image.copy(data, 45);
  return {genesisHash: 'expected-cluster',
    program: {data:program, executable:true, lamports:1, owner:UPGRADEABLE_LOADER, rentEpoch:0},
    programData: {data, executable:false, lamports:1, owner:UPGRADEABLE_LOADER, rentEpoch:0}};
}
function check(state: Snapshot) {return verifyReleaseReadiness(programId, 'expected-cluster', image, state);}
describe('read-only release readiness', () => {
  it('accepts only matching immutable code on the pinned cluster', () => {
    const result = check(snapshot());
    expect(result.upgradeAuthority).to.equal(null);
    expect(result.imageSha256).to.match(/^[a-f0-9]{64}$/);
  });
  it('rejects a retained upgrade authority', () => {
    const state=snapshot(); state.programData!.data[12]=1;
    expect(() => check(state)).to.throw('Upgrade authority');
  });
  it('fails closed on a malformed authority option', () => {
    const state=snapshot(); state.programData!.data[12]=2;
    expect(() => check(state)).to.throw('Upgrade authority');
  });
  it('rejects another cluster', () => {
    const state=snapshot(); state.genesisHash='other-cluster';
    expect(() => check(state)).to.throw('genesis hash');
  });
  it('rejects mismatched code even after authority removal', () => {
    const state=snapshot(); state.programData!.data[49]^=1;
    expect(() => check(state)).to.throw('bytecode');
  });
  it('rejects nonzero additional code after the reviewed image', () => {
    const state=snapshot(); state.programData!.data[state.programData!.data.length-1]=1;
    expect(() => check(state)).to.throw('bytecode');
  });
  it('rejects a different ProgramData binding', () => {
    const state=snapshot(); state.program!.data[4]^=1;
    expect(() => check(state)).to.throw('binding');
  });
  it('rejects accounts owned by another loader', () => {
    const state=snapshot(); state.programData!.owner=PublicKey.default;
    expect(() => check(state)).to.throw('ProgramData');
  });
  it('rejects missing accounts', () => {
    const state=snapshot(); state.programData=null;
    expect(() => check(state)).to.throw('ProgramData');
    state.program=null;
    expect(() => check(state)).to.throw('absent');
  });
  it('rejects truncated metadata and non-executable programs', () => {
    const state=snapshot(); state.programData!.data=Buffer.alloc(12);
    expect(() => check(state)).to.throw('ProgramData');
    state.program!.executable=false;
    expect(() => check(state)).to.throw('non-executable');
  });
});
describe('release readiness across RPCs (A6-H3)', () => {
  const across = (states: Snapshot[], min = 2) => verifyAcrossRpcs(programId, 'expected-cluster', image, states, min);
  it('passes when every RPC passes and they agree, and emits the app manifest', () => {
    const result = across([snapshot(), snapshot()]);
    expect(result.rpcs).to.equal(2);
    expect(result.manifest.image).to.deep.equal({sha256: result.imageSha256, length: image.length});
    expect(result.manifest.programId).to.equal(programId.toBase58());
  });
  it('needs enough RPCs', () => {
    expect(() => across([snapshot()], 2)).to.throw('independent RPCs');
  });
  it('fails when any RPC fails or they disagree', () => {
    const bad = snapshot(); bad.programData!.data[12] = 1;
    expect(() => across([snapshot(), bad])).to.throw('Upgrade authority');
    const other = snapshot(); other.programData!.data.writeBigUInt64LE(124n, 4);
    expect(() => across([snapshot(), other])).to.throw('disagree');
  });
});
