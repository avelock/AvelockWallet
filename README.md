# Avelock Wallet — contract sources

Self-custody vault with on-chain withdrawal delays. This repository
contains the contract and script sources for every supported network —
EVM chains, TRON, TON, Solana, Bitcoin and Litecoin — published so anyone
can verify what runs on-chain (Etherscan / Tronscan / verifier.ton.org, or
by rebuilding a Bitcoin/Litecoin address), with the tests for each and the
Bitcoin/Litecoin co-signer. The mobile app is not published here yet.

Every Vault follows the same rules on every network:

- a withdrawal is requested first and can be confirmed only after the
  owner-chosen delay, and only to an address on the Vault's allowlist;
- a new allowed address waits its own delay; any settings change waits the
  policy delay and never less than the current withdrawal delay, so a
  stolen key cannot shorten the delay faster than it could simply wait;
- stopping actions (cancel, lock) are always immediate;
- optional **guard keys** can cancel a pending withdrawal or trigger a
  **Panic Lock**, but can never move funds, add addresses or unlock;
  lifting a lock waits `lockDelay` (never less than the withdrawal delay).
  A lock also drops every queued change, including a queued removal of a
  guard, and a guard cannot be removed while the Vault is locked.

All networks are test networks for now, and the code is not audited yet.


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
| Solana | [`networks/solana`](networks/solana) | [`contracts/solana`](contracts/solana) (Devnet, upgradeable) |
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
  NFT withdrawal path, guard keys and Panic Lock). `protocolVersion()`
  returns 0 for this revision.

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
  module, same state machine as the EVM side, including guard keys and
  Panic Lock.

Both TON contracts report `protocolVersion()` = **1**. Protocol 1 fixes one
behaviour of protocol 0: setting a policy parameter back to its current
value now withdraws a change queued for that parameter (in protocol 0 the
queued change stayed and could still be applied later). Vaults created
with protocol 0 keep working and keep their old code — contracts are never
upgraded in place.

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
  not something this contract can close unilaterally. The Avelock app
  therefore reads the whole message trace from two independent indexers
  and reports "delivered" or "failed" only when both agree; it never
  resends a withdrawal on its own.

## Solana (devnet)

- `contracts/solana` — one shared Anchor program; each Vault is a PDA of
  the owner key (`["avelock-vault", owner]`) with its permanent security
  extension (`["avelock-extension", vault]`). Same rules as the other
  networks: delayed withdrawals to allowed addresses only, delayed policy
  changes, guard keys and Panic Lock. SOL, SPL tokens and NFTs.
- Program id `9r172eBe2XJ9PPFH8rmb6XbxNkrNLkMnqBZmSfCwUiXD`, deployed on
  Devnet and **still upgradeable**. Before any Vault holds real value the
  program must be made immutable and checked against a reviewed build of
  this source. Build and test: `cd contracts/solana && cargo test --locked`.

## Bitcoin (signet) and Litecoin (testnet)

Bitcoin has no deployed contract: the vault's rules are the address
itself, a Taproot output with no usable key path (BIP-341 NUMS internal
key) and one script leaf per spending path:

- **cosigned** — owner + `threshold` of the Avelock signers, spendable
  immediately. New vaults use **2 of 3** independent signers (one leaf per
  pair of signers), so no single signer can block or approve a spend.
  Delays, the allowlist and Panic Lock on this path are enforced by the
  signers, off-chain; if they disagree, the app stops and treats it as an
  alarm.
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

## Co-signer (Bitcoin and Litecoin)

`contracts/utxo/src/signer` — the co-signer service. It keeps each vault's
policy (delays, allowlist, guard keys, Panic Lock, fee cap) and signs a
spend only when that policy allows it; every operation is signed by the
owner's key and advances a hash-chained state head the app checks. Three
independent operators run one each; any two co-sign.

## RPC proxy

`rpc-proxy` — the Cloudflare Worker behind `rpc.avelock.app` that the app reads every network through. It only delivers: provider keys stay on the server, only the methods the app uses pass, and the app cross-checks security-relevant reads (pending withdrawals, lock state, allowlist, vault code) against independent public nodes, so a lying proxy shows up as an alarm instead of a wrong answer. Also serves the network status page. `cd rpc-proxy && npm test`.

## Tests

| Folder | Command |
|---|---|
| `contracts/evm` | `forge test` |
| `contracts/ton` | `npm ci && npm test` |
| `contracts/solana` | `cargo test --manifest-path programs/avelock_wallet/Cargo.toml` (unit), `anchor test` (local validator) |
| `contracts/utxo` | `npm ci && npm test` |
| `rpc-proxy` | `npm test` |

## License

Avelock Wallet is free and open-source software under the [GNU General Public License v3.0](LICENSE) (GPL-3.0-only): anyone may use, study, modify and share it, and any distributed modified version must be released under the same license. See [NOTICE](NOTICE). Third-party dependencies (for example `lib/forge-std`) keep their own licenses.
