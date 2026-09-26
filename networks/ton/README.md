# Avelock on TON

Test network: **TON Testnet** · explorer: https://testnet.tonscan.org

**Source:** [`contracts/ton`](../../contracts/ton) — Tact contracts.

## How a Vault is created

Two contracts: `AvelockWallet`
([`avelock_wallet.tact`](../../contracts/ton/contracts/avelock_wallet.tact)) and its
permanent security module `AvelockSecurityExtension`
([`avelock_security_extension.tact`](../../contracts/ton/contracts/avelock_security_extension.tact)).
Both addresses are derived from the owner key and the chosen policy; deploy and
fund both before depositing.

Current contracts report `protocolVersion()` = 1: setting a policy parameter
back to its current value withdraws a change queued for it. Vaults created with
protocol 0 keep their code and keep working.

## Operational balance

The module pays the network fees of owner operations (~0.001–0.002 TON each)
and attaches 0.01 TON to each native withdrawal (most of it stays in the
wallet). It needs at least 0.07 TON to confirm a withdrawal; top it up like any
active contract.

## What a Vault holds

TON, jettons (including USDT) and NFTs.

Build: `cd contracts/ton && npm ci && npx tact --config tact.config.json`.
