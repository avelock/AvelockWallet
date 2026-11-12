// Cloudflare Worker entry. Provider keys are Worker secrets
// (`wrangler secret put TONCENTER_KEY`, etc.). Each client IP gets a
// request budget (review RPC-4), charged one unit per JSON-RPC call
// (round2 H-1). No request logging.
import { handle, limitKey } from './proxy.mjs';

const json = (status, body, extra = {}) =>
  new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json', ...extra } });

export default {
  async fetch(request, env, ctx) {
    try {
      // Without its limiter the proxy does not serve (round2 L-7): a renamed
      // or dropped binding must not mean "no limit". ALLOW_NO_LIMIT=1 only for local dev.
      if ((!env.PER_IP || !env.SHARED) && env.ALLOW_NO_LIMIT !== '1') return json(503, { error: 'limiter not configured' });
      const key = limitKey(request.headers.get('cf-connecting-ip'));
      const take = async () => !env.PER_IP || (await env.PER_IP.limit({ key })).success;
      if (!(await take())) return json(429, { error: 'rate limited' }, { 'Retry-After': '60' });
      const charge = async n => {
        for (let i = 0; i < n; i++) if (!(await take())) return false;
        return true;
      };
      // The shared budget per route (round2 H-1): one unit per weight.
      const shared = async (route, weight) => {
        if (!env.SHARED) return true;
        for (let i = 0; i < weight; i++) if (!(await env.SHARED.limit({ key: route })).success) return false;
        return true;
      };
      return await handle(request, env, fetch, charge, shared, p => ctx?.waitUntil(p));
    } catch {
      // Nothing a client sends ends in Cloudflare's error page (round2 L-6).
      return json(500, { error: 'proxy error' });
    }
  },
};
