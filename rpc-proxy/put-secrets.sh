#!/bin/sh
# Sends every filled value in secrets.env to the Cloudflare Worker as a
# secret. Values are piped to wrangler and never printed.
set -eu
cd "$(dirname "$0")"
[ -f secrets.env ] || { echo "Copy secrets.env.example to secrets.env and fill it in first."; exit 1; }
grep -E '^[A-Z_]+=.+' secrets.env | while IFS='=' read -r name value; do
  printf '%s' "$value" | npx wrangler secret put "$name" >/dev/null
  echo "set $name"
done
echo "Done. You can delete secrets.env now."
