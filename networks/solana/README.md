# Avelock on Solana

Test network: **Devnet** · explorer: https://explorer.solana.com/?cluster=devnet

**Source:** [`contracts/solana`](../../contracts/solana) — an Anchor program.

**Status: not deployed yet.** The program id declared in the source is
`9r172eBe2XJ9PPFH8rmb6XbxNkrNLkMnqBZmSfCwUiXD`. Before any Vault holds real
value, the deployed program must be made immutable (no upgrade authority) and
checked against a reviewed build of this source.

## How a Vault works

Unlike the EVM networks, nothing is deployed per user: one shared program owns
every Vault. A user's Vault is a PDA derived from the owner key
(`["avelock-vault", owner]`), created by `initialize_vault` together with its
permanent security extension (`["avelock-extension", vault]`) and the
owner-chosen policy. Creating one only costs account rent.

- SOL is held by the Vault PDA itself; SPL tokens and NFTs by its associated
  token accounts.
- Withdrawals: `request_*_withdrawal` → wait the delay → `confirm_*_withdrawal`,
  only to an allowed address; `cancel_withdrawal` at any time before.
- Finished requests can be closed (`prune_request`) to return their rent.

Build and test: `cd contracts/solana && cargo test --locked` (build the SBF
artifact with `anchor build --no-idl`).
