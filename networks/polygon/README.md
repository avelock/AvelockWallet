# Avelock on Polygon

Test network: **Amoy** (chain id 80002) · explorer: https://amoy.polygonscan.com

**Source:** [`contracts/evm`](../../contracts/evm) — the same Solidity code runs on every EVM network.

## How a Vault is created

Each Vault is a pair of EIP-1167 clones (wallet + security module) created and
bound in one transaction by `AvelockVaultFactory`
([`contracts/evm/src/AvelockVaultFactory.sol`](../../contracts/evm/src/AvelockVaultFactory.sol)).
The caller is always the owner.

The factory is deployed through the deterministic CREATE2 deployer
`0x4e59b44847b379578588920ca78fbf26c0b4956c` with salt `0`, so its address is
derived from its exact code and is the same on every network.

Not deployed on Amoy yet. The first Vault created on this network deploys it through the deterministic deployer, at the same address: `0xFfb6Ed4115B44D80285CE06b4ced7d409c25603D`.

## What a Vault holds

POL, ERC-20 tokens (test USDC), NFTs. Incoming funds are never delayed; every withdrawal waits the Vault's
delay and can only go to an allowed address.

## Verify a Vault

1. `factory.vaultOf(owner)` returns the Vault wallet.
2. The wallet and its module must have the EIP-1167 runtime
   `363d3d373d3d3d363d73<implementation>5af43d82803e903d91602b57fd5bf3`, where
   `<implementation>` is `factory.walletImplementation()` /
   `factory.extensionImplementation()`.
3. `wallet.owner()` is the owner, `wallet.securityExtension()` is the module,
   `module.wallet()` is the wallet.

Build: `cd contracts/evm && forge build`.
