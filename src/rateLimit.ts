import type { Context, Next } from 'hono';
import { sql } from './db.js';
import { getClientIp } from './ip.js';

export interface RateLimitOptions {
  /** Requests allowed per window before a bucket starts returning 429. */
  max: number;
  windowMs: number;
  /** Distinguishes independent limiters (e.g. "post" vs "get") sharing the same table. */
  keyPrefix: string;
  /** Extra key component, e.g. the note id, for a limiter scoped tighter than per-IP. */
  keySuffix?: (c: Context) => string;
}

/**
 * Fixed-window rate limiting backed by Postgres — the only persistent store
 * already available to this stateless Vercel function. Not perfectly
 * precise (fixed windows allow a burst near the boundary), but enough to
 * stop trivial POST spam and password brute-forcing; an IP-rotating
 * attacker isn't covered without a lot more machinery, out of scope here.
 */
export function rateLimit(opts: RateLimitOptions) {
  return async (c: Context, next: Next) => {
    const ip = getClientIp(c);
    const windowStart = Math.floor(Date.now() / opts.windowMs) * opts.windowMs;
    const suffix = opts.keySuffix ? `:${opts.keySuffix(c)}` : '';
    const bucketKey = `${opts.keyPrefix}:${ip}${suffix}:${windowStart}`;

    const rows = await sql`
      insert into rate_limits (bucket_key, count, window_start)
      values (${bucketKey}, 1, to_timestamp(${windowStart / 1000}))
      on conflict (bucket_key) do update set count = rate_limits.count + 1
      returning count
    `;
    const count = (rows[0] as { count: number }).count;

    if (count > opts.max) {
      const retryAfterSeconds = Math.ceil((windowStart + opts.windowMs - Date.now()) / 1000);
      c.header('retry-after', String(Math.max(retryAfterSeconds, 1)));
      return c.json({ error: 'rate limit exceeded, try again later' }, 429);
    }

    await next();
  };
}
