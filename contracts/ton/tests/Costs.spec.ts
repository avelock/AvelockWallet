// Measures how much TON the security module spends per owner operation
// (sandbox with default basechain gas/fee config). Informational: prints costs.
import {Blockchain} from '@ton/sandbox';
import {beginCell, Dictionary, toNano, fromNano} from '@ton/core';
import {keyPairFromSeed, sign} from '@ton/crypto';
import {AvelockWallet} from '../build/AvelockWallet/AvelockWallet_AvelockWallet';
import {AvelockSecurityExtension} from '../build/AvelockSecurityExtension/AvelockSecurityExtension_AvelockSecurityExtension';
import '@ton/test-utils';
const keys=keyPairFromSeed(Buffer.alloc(32,17));
const owner=BigInt('0x'+keys.publicKey.toString('hex'));
const DELAYS = [86400n,604800n,86400n,604800n,86400n,86400n] as const;
it('module and vault cost per operation', async()=>{
 const chain=await Blockchain.create(); chain.now=1800000000;
 const config=Dictionary.loadDirect(Dictionary.Keys.Int(32),Dictionary.Values.Cell(),chain.config);
 config.set(19,beginCell().storeInt(-3,32).endCell());
 chain.setConfig(beginCell().storeDictDirect(config).endCell());
 const source=await chain.treasury('funding'); const destination=await chain.treasury('recipient');
 const wallet=chain.openContract(await AvelockWallet.fromInit(owner,-3n,...DELAYS));
 const extension=chain.openContract(await AvelockSecurityExtension.fromInit(owner,-3n,wallet.address,...DELAYS));
 await wallet.send(source.getSender(),{value:toNano('5')},null);
 await extension.send(source.getSender(),{value:toNano('1')},null);
 const send=async(op:number, write:(b:ReturnType<typeof beginCell>)=>void)=>{
  const b=beginCell().storeAddress(extension.address).storeInt(-3,32).storeUint(await extension.getSeqno(),32).storeUint(chain.now!+600,32).storeUint(op,8);write(b);if(op===3)b.storeMaybeRef(null).storeBit(true);
  const payload=b.endCell();return extension.sendExternal(beginCell().storeBuffer(sign(payload.hash(),keys.secretKey)).storeRef(payload).endCell().asSlice());
 };
 const bal=async()=>({e:(await chain.getContract(extension.address)).balance,w:(await chain.getContract(wallet.address)).balance});
 const measure=async(name:string, fn:()=>Promise<unknown>)=>{
  const a=await bal(); await fn(); const b=await bal();
  console.log(`${name}: module ${fromNano(b.e-a.e)} TON, vault ${fromNano(b.w-a.w)} TON`);
 };
 await measure('add allowed address', ()=>send(1,b=>b.storeAddress(destination.address)));
 chain.now!+=604801;
 await measure('request withdrawal 1 TON', ()=>send(3,b=>b.storeAddress(destination.address).storeCoins(toNano('1')).storeUint(0,2)));
 chain.now!+=86400;
 await measure('confirm withdrawal', ()=>send(5,b=>b.storeUint(0,64)));
 await measure('request withdrawal 1 TON', ()=>send(3,b=>b.storeAddress(destination.address).storeCoins(toNano('1')).storeUint(0,2)));
 await measure('cancel withdrawal', ()=>send(4,b=>b.storeUint(1,64)));
});
