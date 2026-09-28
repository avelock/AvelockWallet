import {WalletContractV5R1} from '@ton/ton';
import {Blockchain} from '@ton/sandbox';
import {Address, beginCell, Dictionary, toNano, internal, SendMode} from '@ton/core';
import {keyPairFromSeed, sign} from '@ton/crypto';
import {AvelockWallet} from '../build/AvelockWallet/AvelockWallet_AvelockWallet';
import {AvelockSecurityExtension} from '../build/AvelockSecurityExtension/AvelockSecurityExtension_AvelockSecurityExtension';
import '@ton/test-utils';
const keys=keyPairFromSeed(Buffer.alloc(32,17));
const owner=BigInt('0x'+keys.publicKey.toString('hex'));
const DELAYS = [86400n,604800n,86400n,604800n,86400n,86400n] as const;
async function setup(value='1') {
 const chain=await Blockchain.create(); chain.now=1800000000;
 const config=Dictionary.loadDirect(Dictionary.Keys.Int(32),Dictionary.Values.Cell(),chain.config);
 config.set(19,beginCell().storeInt(-3,32).endCell());
 chain.setConfig(beginCell().storeDictDirect(config).endCell());
 const source=await chain.treasury('funding'); const destination=await chain.treasury('recipient');
 const wallet=chain.openContract(await AvelockWallet.fromInit(owner,-3n,...DELAYS));
 const extension=chain.openContract(await AvelockSecurityExtension.fromInit(owner,-3n,wallet.address,...DELAYS));
 await wallet.send(source.getSender(),{value:toNano('1')},null);
 await extension.send(source.getSender(),{value:toNano(value)},null);
 const send=async(op:number, write:(b:ReturnType<typeof beginCell>)=>void, network=-3, secretKey=keys.secretKey)=>{
  const b=beginCell().storeAddress(extension.address).storeInt(network,32).storeUint(await extension.getSeqno(),32).storeUint(chain.now!+600,32).storeUint(op,8);write(b);if(op===3)b.storeMaybeRef(null).storeBit(true);
  const payload=b.endCell();return extension.sendExternal(beginCell().storeBuffer(sign(payload.hash(),secretKey)).storeRef(payload).endCell().asSlice());
 };
 const request=async()=>{
  await send(1,b=>b.storeAddress(destination.address)); chain.now!+=604801;
  await send(3,b=>b.storeAddress(destination.address).storeCoins(toNano('0.01')).storeUint(0,2));
 };
 return {chain,source,destination,wallet,extension,send,request};
}
it('selects the exact module at initialization without a bootstrap signature',async()=>{
 const {wallet,extension}=await setup();
 expect(await wallet.getIsExtension(extension.address)).toBe(true);
 expect(await wallet.getProtocolVersion()).toBe(1n);
 expect(await extension.getNetworkGlobalId()).toBe(-3n);
 expect((await AvelockWallet.fromInit(owner,-239n,...DELAYS)).address.equals(wallet.address)).toBe(false);
});
it('checks the signed network domain before consuming seqno',async()=>{
 const {extension,send,destination}=await setup();
 await expect(send(1,b=>b.storeAddress(destination.address),-239)).rejects.toBeDefined();
 expect(await extension.getSeqno()).toBe(0n);
 await send(1,b=>b.storeAddress(destination.address));expect(await extension.getSeqno()).toBe(1n);
});
it('prunes canceled records and reverse lookup without reusing IDs',async()=>{
 const {extension,send,request}=await setup();await request();
 await send(4,b=>b.storeUint(0,64));await send(12,b=>b.storeUint(0,64));
 expect(await extension.getRequest(0n)).toBeNull();
 expect(await extension.getRequestIdForOperation(1n)).toBeNull();
 expect(await extension.getNextRequestId()).toBe(1n);
});
it('keeps pending and submitted records needed for lifecycle/bounce handling',async()=>{
 const {extension,send,request,chain}=await setup();await request();
 expect((await send(12,b=>b.storeUint(0,64))).transactions).toHaveTransaction({to:extension.address,success:true}); expect(await extension.getLastFailureCode()).toBe(66n);
 chain.now!+=86400;await send(5,b=>b.storeUint(0,64));
 expect((await extension.getRequest(0n))?.submitted).toBe(true);
 expect((await send(12,b=>b.storeUint(0,64))).transactions).toHaveTransaction({to:extension.address,success:true}); expect(await extension.getLastFailureCode()).toBe(66n);
});
it('archives an old submitted request and clears wallet correlation without claiming settlement',async()=>{
 const {extension,wallet,source,send,request,chain}=await setup();await request();
 chain.now!+=86400;await send(5,b=>b.storeUint(0,64));
 expect(await wallet.getCorrelationDestination(0n)).not.toBeNull();
 const early = await wallet.send(source.getSender(), {value:toNano('0.02')}, {$$type:'PruneCorrelation',requestId:0n});
 expect(early.transactions).toHaveTransaction({to:wallet.address,success:false,exitCode:66});
 expect((await extension.getRequest(0n))?.submitted).toBe(true);
 chain.now!+=86400+15724800+1;
 const result=await send(12,b=>b.storeUint(0,64));
 expect(result.transactions).toHaveTransaction({to:extension.address,success:true});
 expect(await extension.getRequest(0n)).toBeNull();
 expect(await wallet.getCorrelationDestination(0n)).toBeNull();
 const repeat = await wallet.send(source.getSender(), {value:toNano('0.02')}, {$$type:'PruneCorrelation',requestId:0n});
 expect(repeat.transactions).toHaveTransaction({to:wallet.address,success:true});
});
it('reports the reserve and keeps a low-gas withdrawal unsubmitted',async()=>{
 const {extension,request,send,chain}=await setup('0.06');await request();chain.now!+=86400;
 expect(await extension.getMinimumOperationalBalance()).toBe(toNano('0.07'));
 expect((await send(5,b=>b.storeUint(0,64))).transactions).toHaveTransaction({to:extension.address,success:true}); expect(await extension.getLastFailureCode()).toBe(64n);
 expect((await extension.getRequest(0n))?.submitted).toBe(false);
});
it('also checks the actual TVM network rather than trusting only stored/signed values', async()=>{
 const {chain,extension,send,destination}=await setup();
 const config=Dictionary.loadDirect(Dictionary.Keys.Int(32),Dictionary.Values.Cell(),chain.config);
 config.set(19,beginCell().storeInt(-239,32).endCell());
 chain.setConfig(beginCell().storeDictDirect(config).endCell());
 await expect(send(1,b=>b.storeAddress(destination.address),-3)).rejects.toBeDefined();
 expect(await extension.getSeqno()).toBe(0n);
});
it('reserves all former rotation operations without consuming nonce or replacing the owner',async()=>{
 const {wallet,extension,send,chain,destination}=await setup();
 const replacement=keyPairFromSeed(Buffer.alloc(32,42));
 const newOwner=BigInt('0x'+replacement.publicKey.toString('hex'));
 for (const key of [0n,newOwner]) {
  await expect(send(13,b=>b.storeUint(key,256))).rejects.toBeDefined();
 }
 chain.now!+=31536000;
 for (const op of [14,15]) await expect(send(op,b=>{})).rejects.toBeDefined();
 expect(await extension.getSeqno()).toBe(0n);
 expect(await wallet.getOwnerPublicKey()).toBe(owner);
 expect(await extension.getOwnerPublicKey()).toBe(owner);
 await send(1,b=>b.storeAddress(destination.address));
 expect(await extension.getSeqno()).toBe(1n);
});

it('deploys both contracts from a network-bound V5 setup wallet',async()=>{
 const chain=await Blockchain.create();
 const config=Dictionary.loadDirect(Dictionary.Keys.Int(32),Dictionary.Values.Cell(),chain.config);
 config.set(19,beginCell().storeInt(-3,32).endCell());chain.setConfig(beginCell().storeDictDirect(config).endCell());
 const source=await chain.treasury('V5 funding');
 const wallet=chain.openContract(await AvelockWallet.fromInit(owner,-3n,...DELAYS));
 const extension=chain.openContract(await AvelockSecurityExtension.fromInit(owner,-3n,wallet.address,...DELAYS));
 const funding=chain.openContract(WalletContractV5R1.create({publicKey:keys.publicKey,walletId:{networkGlobalId:-3,context:{workchain:0,walletVersion:'v5r1',subwalletNumber:0}}}));
 await source.send({to:funding.address,value:toNano('0.3'),bounce:false});
 const result=await funding.sendTransfer({seqno:0,secretKey:keys.secretKey,sendMode:SendMode.PAY_GAS_SEPARATELY|SendMode.IGNORE_ERRORS,messages:[
  internal({to:wallet.address,init:wallet.init,value:toNano('0.05'),bounce:false}),
  internal({to:extension.address,init:extension.init,value:toNano('0.2'),bounce:false}),
 ]});
 expect(result.transactions).toHaveTransaction({to:wallet.address,deploy:true,success:true});
 expect(result.transactions).toHaveTransaction({to:extension.address,deploy:true,success:true});
 expect(await wallet.getIsExtension(extension.address)).toBe(true);
 expect(await extension.getOperationalBalance()).toBeGreaterThan(toNano('0.07'));
});

it('activates a typed asset independently of recipient allowlisting and preserves its first deadline', async () => {
 const {extension,wallet,send,chain,destination}=await setup();
 const asset=(await chain.treasury('registered item')).address;
 const register=()=>send(16,b=>b.storeAddress(asset).storeUint(2,2).storeRef(beginCell().storeAddress(destination.address)));
 const started=chain.now!;
 await register();
 expect((await extension.getAssetRegistration(asset))?.activeAt).toBe(BigInt(started+604800));
 expect(await extension.getIsAssetActive(asset,2n)).toBe(false);
 chain.now!+=100;await register();
 expect((await extension.getAssetRegistration(asset))?.activeAt).toBe(BigInt(started+604800));
 chain.now=started+604800;
 expect(await extension.getIsAssetActive(asset,2n)).toBe(true);
 expect(await extension.getIsAssetActive(asset,1n)).toBe(false);
 expect(await extension.getIsAddressActive(asset)).toBe(false);
 // Asset authorization never permits a native withdrawal to that address.
 const result=await send(3,b=>b.storeAddress(asset).storeCoins(1).storeUint(0,2));
 expect((result).transactions).toHaveTransaction({to:extension.address,success:true}); expect(await extension.getLastFailureCode()).toBe(52n);
 expect(await wallet.getIsExtension(asset)).toBe(false);
});
it('recipient allowlisting cannot replace asset registration', async () => {
 const {extension,send,chain,destination}=await setup();
 await send(1,b=>b.storeAddress(destination.address));chain.now!+=604800;
 expect(await extension.getIsAddressActive(destination.address)).toBe(true);
 expect(await extension.getIsAssetActive(destination.address,2n)).toBe(false);
 const result=await send(3,b=>b.storeAddress(destination.address).storeCoins(1).storeUint(2,2).storeRef(beginCell().storeAddress(destination.address)));
 expect((result).transactions).toHaveTransaction({to:extension.address,success:true}); expect(await extension.getLastFailureCode()).toBe(67n);
});
it('re-registration cannot revive a withdrawal created before asset revocation', async () => {
 const {extension,send,chain,destination}=await setup();
 const asset=(await chain.treasury('revocable asset')).address;
 await send(1,b=>b.storeAddress(destination.address));
 const register=()=>send(16,b=>b.storeAddress(asset).storeUint(2,2).storeRef(beginCell().storeAddress(destination.address)));
 await register();chain.now!+=604800;
 // A longer confirmation window keeps the original request unexpired throughout re-registration.
 await send(11,b=>b.storeUint(2592000,32));chain.now!+=604800;
 await send(9,b=>b.storeUint(3,8));
 await send(3,b=>b.storeAddress(destination.address).storeCoins(1).storeUint(2,2).storeRef(beginCell().storeAddress(asset)));
 expect(await extension.getNextRequestId()).toBe(1n);
 await send(17,b=>b.storeAddress(asset));
 expect(await extension.getAssetRegistration(asset)).toBeNull();
 await register();chain.now!+=604800;
 expect(await extension.getIsAssetActive(asset,2n)).toBe(true);
 const result=await send(5,b=>b.storeUint(0,64));
 expect((result).transactions).toHaveTransaction({to:extension.address,success:true}); expect(await extension.getLastFailureCode()).toBe(67n);
 expect((await extension.getRequest(0n))?.submitted).toBe(false);
});
it('an existing registration cannot silently change its type or root', async () => {
 const {extension,send,destination,wallet}=await setup();
 await send(16,b=>b.storeAddress(destination.address).storeUint(2,2).storeRef(beginCell().storeAddress(wallet.address)));
 const result=await send(16,b=>b.storeAddress(destination.address).storeUint(1,2).storeRef(beginCell().storeAddress(wallet.address)));
 expect((result).transactions).toHaveTransaction({to:extension.address,success:true}); expect(await extension.getLastFailureCode()).toBe(67n);
 expect((await extension.getAssetRegistration(destination.address))?.kind).toBe(2n);
 const changedRoot=await send(16,b=>b.storeAddress(destination.address).storeUint(2,2).storeRef(beginCell().storeAddress(destination.address)));
 expect((changedRoot).transactions).toHaveTransaction({to:extension.address,success:true}); expect(await extension.getLastFailureCode()).toBe(67n);
});

it('asset activation never shortens the existing destination delay when policy delay is shorter', async () => {
 const {extension,send,chain,destination}=await setup();
 await send(8,b=>b.storeUint(1,32));chain.now!+=604800;
 await send(9,b=>b.storeUint(2,8));
 expect(await extension.getPolicyDelay()).toBe(1n);
 const now=chain.now!;
 await send(16,b=>b.storeAddress(destination.address).storeUint(2,2).storeRef(beginCell().storeAddress(destination.address)));
 expect((await extension.getAssetRegistration(destination.address))?.activeAt).toBe(BigInt(now+604800));
 chain.now!+=2;
 expect(await extension.getIsAssetActive(destination.address,2n)).toBe(false);
});

it('rejects creation with a zero owner key', async () => {
 const {chain,source}=await setup();
 const invalid=chain.openContract(await AvelockWallet.fromInit(0n,-3n,...DELAYS));
 const result=await invalid.send(source.getSender(),{value:toNano('0.05')},null);
 expect(result.transactions).toHaveTransaction({to:invalid.address,success:false,exitCode:61});
});

it('accepts deposits and gas top-ups that carry a text comment', async () => {
 const { source, wallet, extension } = await setup();
 const comment = (text: string) => beginCell().storeUint(0, 32).storeStringTail(text).endCell();
 for (const target of [wallet.address, extension.address]) {
  const r = await source.send({ to: target, value: toNano('1'), body: comment('memo 12345') });
  expect(r.transactions).toHaveTransaction({ to: target, success: true, aborted: false });
 }
});

it('accepts incoming NFT ownership_assigned and jetton transfer_notification messages', async () => {
 const { source, wallet } = await setup();
 const ownershipAssigned = beginCell().storeUint(0x05138d91, 32).storeUint(1, 64).storeAddress(source.address).storeBit(false).endCell();
 const transferNotification = beginCell().storeUint(0x7362d09c, 32).storeUint(1, 64).storeCoins(100).storeAddress(source.address).storeBit(false).endCell();
 for (const body of [ownershipAssigned, transferNotification]) {
  const r = await source.send({ to: wallet.address, value: toNano('0.05'), body });
  expect(r.transactions).toHaveTransaction({ to: wallet.address, success: true, aborted: false });
 }
});
