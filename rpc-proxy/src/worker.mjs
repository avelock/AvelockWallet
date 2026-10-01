// Cloudflare Worker entry. Provider keys are Worker secrets
// (`wrangler secret put TONCENTER_KEY`, etc.). Each client IP gets a
// request budget (review RPC-4). No request logging.
import { handle, limitKey } from './proxy.mjs';

export default {
  async fetch(request, env) {
    const ip = request.headers.get('cf-connecting-ip') || 'unknown';
    if (env.PER_IP) {
      const { success } = await env.PER_IP.limit({ key: limitKey(ip) });
      if (!success) {
        return new Response(JSON.stringify({ error: 'rate limited' }), {
          status: 429, headers: { 'Content-Type': 'application/json', 'Retry-After': '60' },
        });
      }
    }
    return handle(request, env);
  },
};
