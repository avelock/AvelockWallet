# Avelock RPC proxy

One handler (`src/proxy.mjs`) for every network the app reads. Provider API
keys live here, never in the app. The proxy is delivery only: the app does
not trust it for security checks (those use independent sources).

- Allow-lists: JSON-RPC methods and REST paths the app uses; everything else is 403.
- Bodies up to 128 KB, batches up to 20 calls; client headers are dropped.
- No request logging.

## Cloudflare Worker (main)

```
npx wrangler login
npx wrangler secret put TONCENTER_KEY      # optional provider keys
npx wrangler secret put TRONGRID_KEY
npx wrangler secret put SOL_DEVNET_URL     # a provider URL including its key
npx wrangler deploy                        # serves https://rpc.avelock.app
```

A per-IP limit (120 requests a minute, IPv6 counted by /64) is built in
through the Workers rate-limiting binding in `wrangler.toml`. Free plan:
100,000 requests a day.

## Plain server (fallback)

`node src/node.mjs` on 127.0.0.1:8899 behind nginx with TLS; keys in a
systemd `EnvironmentFile` (mode 600); per-IP limit via `RATE_PER_MINUTE`.
A broken request or a failing provider never stops the process.

## App

Build with `AVELOCK_RPC_PROXY=https://rpc.avelock.app`. If the proxy fails,
the app repeats the request at the public endpoint and skips the proxy for
five minutes. A user's own endpoint in Settings always wins.

Tests: `npm test`.

## Status

`GET /status` checks every network once (the same upstream and key the proxy uses) and returns `up` / `degraded` / `down`, the response time and the latest block — no URLs, no keys. The answer is cached for 60 s per Worker instance and allows any origin. The page `status.avelock.app` (folder `status/`) shows it.
