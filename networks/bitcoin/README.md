# Avelock on Bitcoin

Test network: **Signet** · explorer: https://mempool.space/signet

**Source:** [`contracts/utxo`](../../contracts/utxo) — the same Taproot scripts
for Bitcoin and Litecoin.

## How a Vault works

Bitcoin has no smart contracts. The Vault is a Taproot address with no usable
key path and one script leaf per spending path:

- **cosigned** — owner + 2 of 3 independent Avelock signers (one leaf per
  pair), spendable immediately. The withdrawal delay, allowed addresses and
  Panic Lock on this path are enforced by the signers.
- **reserve** — owner alone after the reserve period ~1 year (52,560 blocks of ~10 minutes), enforced by Bitcoin itself. The
  owner never depends on the signer to recover funds.
- **heir** — optional inheritance key, later than the reserve path.

Owner keys: `m/86'/<coin>'/100'/0/<generation>`, coin type 0 on mainnet, 1 on test networks.

Anyone can rebuild a Vault address from its public keys and parameters
([`vault.ts`](../../contracts/utxo/src/vault.ts)) and compare.

Build: `cd contracts/utxo && npm install && npm run build`.
