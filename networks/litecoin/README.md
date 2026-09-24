# Avelock on Litecoin

Test network: **Testnet** · explorer: https://litecoinspace.org/testnet

**Source:** [`contracts/utxo`](../../contracts/utxo) — the same Taproot scripts
for Bitcoin and Litecoin ([`networks.ts`](../../contracts/utxo/src/networks.ts) defines Litecoin).

## How a Vault works

Litecoin has no smart contracts. The Vault is a Taproot address with no usable
key path and one script leaf per spending path:

- **cosigned** — owner + Avelock signer, spendable immediately. The withdrawal
  delay and allowed addresses on this path are enforced by the signer.
- **reserve** — owner alone after the reserve period 100 days (57,600 blocks of ~2.5 minutes; the CSV cap of 65,535 blocks is ~113 days), enforced by Litecoin itself. The
  owner never depends on the signer to recover funds.
- **heir** — optional inheritance key, later than the reserve path.

Owner keys: `m/86'/<coin>'/100'/0/<generation>`, coin type 2 (mainnet and testnet).

Anyone can rebuild a Vault address from its public keys and parameters
([`vault.ts`](../../contracts/utxo/src/vault.ts)) and compare.

Build: `cd contracts/utxo && npm install && npm run build`.
