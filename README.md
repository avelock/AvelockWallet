# Avelock Wallet — contract sources

Self-custody vault with on-chain withdrawal delays. This repository
contains the smart contract sources for both deployed chains, published
for on-chain source verification (Etherscan / verifier.ton.org).

## Ethereum (Sepolia)

- `avelock-wallet/src/AvelockWallet.sol` — base wallet account.
- `avelock-wallet/src/extensions/AvelockSecurityExtension.sol` — Vault
  module (withdrawal delay, address allowlist, security policy delay).

Deployed at:
```
AvelockWallet:            0xC445b4dc1C07189d4C2AE6c55E27E7713709377F
AvelockSecurityExtension: 0x529f639be51125D893651A03F1bF1224ff02DF9e
```

## TON (testnet)

- `avelock-wallet-ton/contracts/avelock_wallet.tact` — base wallet account.
- `avelock-wallet-ton/contracts/avelock_security_extension.tact` — Vault
  module, same state machine as the EVM side.

Deployed at:
```
AvelockWallet:            EQBc_stnyrEvkoyQ6NqxxQ3P5lZMgNYtZv2TUZCTHuOcrWGF
AvelockSecurityExtension: EQBh5-y2XWoLZfu5dsfMJ6WambHtug9TYM2DkCrVwyXpwOjz
```
