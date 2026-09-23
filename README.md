# Avelock Wallet — contract sources

Self-custody vault with on-chain withdrawal delays. This repository
contains the smart contract sources for both supported chains, published
for on-chain source verification (Etherscan / verifier.ton.org). It is
the contract-sources-only mirror of a larger project; application code,
tests and CI live in the private development repository and are not
published here.

## EVM chains and TRON

The same Solidity source is used on Ethereum, Base, Arbitrum, Optimism,
Polygon, BNB Chain and Avalanche (test networks), and on TRON (Nile).

- `avelock-wallet/src/AvelockPersonalVault.sol` — the contract the app
  deploys. Its constructor creates the wallet and its security module in
  one transaction with the owner-chosen initial policy (delays and
  permanent minimums).
- `avelock-wallet/src/AvelockWallet.sol` — base wallet account. Its
  constructor deploys and permanently binds its one security module
  atomically; there is no separate bootstrap step and no owner-execution
  bypass of that module.
- `avelock-wallet/src/extensions/AvelockSecurityExtension.sol` — Vault
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

- `avelock-wallet-ton/contracts/avelock_wallet.tact` — base wallet
  account, same permanent-module-at-construction model as the EVM side,
  plus a `networkGlobalId`-bound signed-message envelope.
- `avelock-wallet-ton/contracts/avelock_security_extension.tact` — Vault
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
  `myBalance() >= minimumOperationalBalance()`, currently 0.12 TON).
  Withdrawals stop working, without any loss of funds, if that balance
  runs out — top it up like any other active contract.
- `submitted` on a request means the withdrawal was forwarded, not that
  it settled. A first-hop or an asset-contract-hop rejection is
  recorded as `failed`; a Jetton/NFT contract that accepts the forwarded
  message but fails its own internal transfer without bouncing cannot
  be detected on-chain — TEP-74/TEP-62 have no standard success
  acknowledgment. This is a property of TON's asynchronous messaging,
  not something this contract can close unilaterally.

## License

Avelock Wallet is licensed under the [Business Source License 1.1](LICENSE) (source-available, not open source). The source can be read, audited, modified and used to verify deployed contracts. Individuals may use it to hold and manage their own assets in their own Vault. Commercial use — including embedding it in wallets, exchanges, custody, SDKs or hosted services — requires a commercial license from Avelock. Each version converts to GPL-2.0-or-later on the Change Date (2030-09-23) or four years after its first public release, whichever comes first. Third-party dependencies (for example `lib/forge-std`) keep their own licenses.
