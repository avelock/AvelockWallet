# Avelock Wallet — contract sources

Self-custody vault with on-chain withdrawal delays. This repository
contains the smart contract sources for both supported chains, published
for on-chain source verification (Etherscan / verifier.ton.org). It is
the contract-sources-only mirror of a larger project; application code,
tests and CI live in the private development repository and are not
published here.


## Networks

| Network | Folder | Source |
|---|---|---|
| Ethereum | [`networks/ethereum`](networks/ethereum) | [`contracts/evm`](contracts/evm) |
| Base | [`networks/base`](networks/base) | [`contracts/evm`](contracts/evm) |
| Arbitrum | [`networks/arbitrum`](networks/arbitrum) | [`contracts/evm`](contracts/evm) |
| Optimism | [`networks/optimism`](networks/optimism) | [`contracts/evm`](contracts/evm) |
| Polygon | [`networks/polygon`](networks/polygon) | [`contracts/evm`](contracts/evm) |
| BNB Chain | [`networks/bnb-chain`](networks/bnb-chain) | [`contracts/evm`](contracts/evm) |
| Avalanche | [`networks/avalanche`](networks/avalanche) | [`contracts/evm`](contracts/evm) |
| Tron | [`networks/tron`](networks/tron) | [`contracts/evm`](contracts/evm) (TVM build) |
| TON | [`networks/ton`](networks/ton) | [`contracts/ton`](contracts/ton) |
| Solana | [`networks/solana`](networks/solana) | [`contracts/solana`](contracts/solana) (not deployed yet) |
| Bitcoin | [`networks/bitcoin`](networks/bitcoin) | [`contracts/utxo`](contracts/utxo) |
| Litecoin | [`networks/litecoin`](networks/litecoin) | [`contracts/utxo`](contracts/utxo) |

Each network folder explains how a Vault is created there, its test-network
addresses and how to verify one. The code itself lives once per technology in
`contracts/`, so every network runs exactly the same reviewed source.

## EVM chains and TRON

The same Solidity source is used on Ethereum, Base, Arbitrum, Optimism,
Polygon, BNB Chain and Avalanche (test networks), and on TRON (Nile).

- `contracts/evm/src/AvelockVaultFactory.sol` — creates each Vault as two
  EIP-1167 minimal proxies (wallet + security module) of immutable
  implementations, bound in one transaction; ~365k gas instead of a
  ~2.76M-gas full deployment. No owner, admin or upgrade. The caller is
  always the Vault owner. It is deployed through the deterministic CREATE2
  deployer (`0x4e59b44847b379578588920ca78fbf26c0b4956c`, salt 0), so its
  address is the same on every chain and is derived from its exact code.
- `contracts/evm/src/AvelockPersonalVault.sol` — full deployment of the
  same two contracts, used where the deterministic deployer is unavailable
  (e.g. TRON). Creates and binds both atomically with the owner-chosen
  initial policy.
- `contracts/evm/src/AvelockWallet.sol` — base wallet account. Its one
  security module is bound by a one-time `initialize()` that only its
  deployer (the factory or the full-deployment receipt) can call, in the
  same transaction that creates it; there is no owner-execution bypass of
  that module.
- `contracts/evm/src/extensions/AvelockSecurityExtension.sol` — Vault
  module (withdrawal delay, address allowlist, security policy delay,
  NFT withdrawal path).

TRON builds use the `tron` Foundry profile (`FOUNDRY_PROFILE=tron forge
build src/AvelockPersonalVault.sol`): London EVM, no CBOR metadata, since
the TVM has no PUSH0/MCOPY/TSTORE.

No current on-chain deployment of this source is endorsed here. Earlier
commits to this repository referenced Sepolia/TON testnet addresses from
an older, since-hardened revision of these contracts — those addresses
do not match this source (different bytecode) and have been removed.
Verify any address against the current source's bytecode hash before
trusting it as a deployment of this revision.

## TON (testnet)

- `contracts/ton/contracts/avelock_wallet.tact` — base wallet
  account, same permanent-module-at-construction model as the EVM side,
  plus a `networkGlobalId`-bound signed-message envelope.
- `contracts/ton/contracts/avelock_security_extension.tact` — Vault
  module, same state machine as the EVM side.

No current on-chain deployment of this source is endorsed here, for the
same reason as above.

### Operational notes for a TON deployment

- The wallet's `init()` only computes its module's address and marks it
  authorized in storage — it does not force the module contract to
  actually be deployed. Deploy and fund **both** contracts before
  depositing; a wallet whose module was never deployed is a permanent
  lockbox with no recovery path.
- `AvelockSecurityExtension` pays TON out of its own balance to forward
  each confirmed withdrawal (`confirmWithdrawal` requires
  `myBalance() >= minimumOperationalBalance()`, currently 0.07 TON; each
  native withdrawal attaches 0.01 TON of gas, most of which stays in the
  wallet).
  Withdrawals stop working, without any loss of funds, if that balance
  runs out — top it up like any other active contract.
- `submitted` on a request means the withdrawal was forwarded, not that
  it settled. A first-hop or an asset-contract-hop rejection is
  recorded as `failed`; a Jetton/NFT contract that accepts the forwarded
  message but fails its own internal transfer without bouncing cannot
  be detected on-chain — TEP-74/TEP-62 have no standard success
  acknowledgment. This is a property of TON's asynchronous messaging,
  not something this contract can close unilaterally.

## Bitcoin (signet) and Litecoin (testnet)

Bitcoin has no deployed contract: the vault's rules are the address
itself, a Taproot output with no usable key path (BIP-341 NUMS internal
key) and one script leaf per spending path:

- **cosigned** — owner + Avelock signer, spendable immediately. Delays and
  the allowlist on this path are enforced by the signer, off-chain.
- **reserve** — owner alone, after `reserveBlocks` (CSV). Works without
  the signer, so the owner never depends on it to recover funds.
- **heir** — optional inheritance key, after `heirBlocks` (> reserve).

Litecoin has Taproot, so the same scripts are used there (`networks.ts`);
its CSV cap (65,535 blocks of 2.5 minutes, ~113 days) limits the reserve
period. Sources: `contracts/utxo/src/vault.ts` (address and leaves),
`keys.ts` (owner key derivation, `m/86'/<coin>'/100'/0/<generation>`, coin 0
Bitcoin, 1 Bitcoin test networks, 2 Litecoin),
`spend.ts` (building and signing spends). Anyone can rebuild a vault
address from its public keys and parameters and compare. `npm install &&
npm run build` compiles them.

## License

Avelock Wallet is licensed under the [Business Source License 1.1](LICENSE) (source-available, not open source). The source can be read, audited, modified and used to verify deployed contracts. Individuals may use it to hold and manage their own assets in their own Vault. Commercial use — including embedding it in wallets, exchanges, custody, SDKs or hosted services — requires a commercial license from Avelock. Each version converts to GPL-2.0-or-later on the Change Date (2030-09-23) or four years after its first public release, whichever comes first. Third-party dependencies (for example `lib/forge-std`) keep their own licenses.
