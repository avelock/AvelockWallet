# Avelock on Tron

Test network: **Nile** · explorer: https://nile.tronscan.org

**Source:** [`contracts/evm`](../../contracts/evm) — the same Solidity code as
the EVM networks, compiled for the TVM.

## How a Vault is created

Tron has no deterministic CREATE2 deployer, so each Vault is a full deployment
of `AvelockPersonalVault`
([`contracts/evm/src/AvelockPersonalVault.sol`](../../contracts/evm/src/AvelockPersonalVault.sol)):
it creates the wallet and its security module and binds them atomically with
the owner-chosen policy.

The TVM follows the EVM up to London (no PUSH0 / MCOPY / TSTORE), so it is
built with the `tron` Foundry profile and no CBOR metadata:

```sh
cd contracts/evm
FOUNDRY_PROFILE=tron forge build src/AvelockPersonalVault.sol
```

## What a Vault holds

TRX and TRC-20 tokens, including USDT.
