// Minimal regtest harness: starts a throwaway bitcoind and talks JSON-RPC.

import { spawn, ChildProcess } from 'child_process';
import { mkdtempSync, rmSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';

export class Regtest {
  private proc?: ChildProcess;
  private dir = '';
  private port = 18443 + Math.floor(Math.random() * 1000);
  private auth = 'Basic ' + Buffer.from('avelock:avelock').toString('base64');
  miningAddress = '';

  async start() {
    this.dir = mkdtempSync(join(tmpdir(), 'avelock-regtest-'));
    this.proc = spawn('bitcoind', [
      '-regtest', `-datadir=${this.dir}`, `-rpcport=${this.port}`, `-port=${this.port + 1000}`,
      '-rpcuser=avelock', '-rpcpassword=avelock', '-listen=0', '-txindex=1',
      '-fallbackfee=0.0001', '-server=1', '-printtoconsole=0',
    ], { stdio: 'ignore' });
    for (let i = 0; i < 100; i++) {
      try { await this.rpc('getblockchaininfo'); break; } catch { await new Promise(r => setTimeout(r, 200)); }
    }
    await this.rpc('createwallet', ['miner']);
    this.miningAddress = await this.rpc('getnewaddress', ['', 'bech32m']);
    await this.mine(101); // coinbase maturity
  }

  async stop() {
    try { await this.rpc('stop'); } catch { /* already down */ }
    await new Promise(r => this.proc?.once('exit', r) ?? r(null));
    rmSync(this.dir, { recursive: true, force: true });
  }

  async rpc<T = any>(method: string, params: unknown[] = [], wallet?: string): Promise<T> {
    const url = `http://127.0.0.1:${this.port}/${wallet ? `wallet/${wallet}` : ''}`;
    const res = await fetch(url, {
      method: 'POST',
      headers: { Authorization: this.auth, 'Content-Type': 'application/json' },
      body: JSON.stringify({ jsonrpc: '1.0', id: method, method, params }),
    });
    const body = await res.json() as { result: T; error: { message: string } | null };
    if (body.error) throw new Error(body.error.message);
    return body.result;
  }

  mine(blocks: number) {
    return this.rpc<string[]>('generatetoaddress', [blocks, this.miningAddress]);
  }

  /** Sends `sats` to `address` from the miner wallet and confirms it. */
  async fund(address: string, sats: number) {
    const txid = await this.rpc<string>('sendtoaddress', [address, sats / 1e8], 'miner');
    await this.mine(1);
    const tx = await this.rpc<any>('getrawtransaction', [txid, true]);
    const vout = tx.vout.findIndex((o: any) => o.scriptPubKey.address === address);
    return { txid, vout, value: sats };
  }

  broadcast(hex: string) {
    return this.rpc<string>('sendrawtransaction', [hex]);
  }

  /** Mempool acceptance result without broadcasting. */
  async test(hex: string) {
    const [r] = await this.rpc<{ allowed: boolean; 'reject-reason'?: string }[]>('testmempoolaccept', [[hex]]);
    return r;
  }
}
