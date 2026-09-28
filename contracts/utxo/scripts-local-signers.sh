#!/bin/sh
# Three independent signers per network on one test machine (own key, own
# state each). Test networks only: for mainnet the three must run on
# separate servers with separate operators (see AUDIT_FINDINGS, A6-H2).
set -e
cd "$(dirname "$0")"
npm run build >/dev/null
for i in 0 1 2; do
  node dist/src/signer/server.js "./signer-data-signet-$i" signet $((8339 + 2 * i)) &
  node dist/src/signer/server.js "./signer-data-ltc-$i" litecoin-testnet $((8340 + 2 * i)) &
done
wait
