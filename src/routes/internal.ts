import { Hono } from 'hono';
import { config } from '../config.js';
import { sql } from '../db.js';

export const internal = new Hono();

// Expired-but-unread notes otherwise just sit inert until their next read
// attempt deletes them lazily. This gives guaranteed prompt cleanup instead,
// triggered by Vercel Cron (see vercel.json) — Vercel attaches
// `Authorization: Bearer $CRON_SECRET` to cron-triggered requests, so
// fail-closed if CRON_SECRET isn't configured rather than running open.
internal.get('/cleanup', async (c) => {
  if (!config.cronSecret || c.req.header('authorization') !== `Bearer ${config.cronSecret}`) {
    return c.json({ error: 'unauthorized' }, 401);
  }

  const deletedNotes = await sql`delete from notes where expires_at <= now() returning id`;
  // Rate-limit windows are self-contained (each bucket key encodes its own
  // window start) and harmless once stale, but sweep old ones anyway so the
  // table doesn't grow unbounded.
  const deletedBuckets = await sql`delete from rate_limits where window_start < now() - interval '1 hour' returning bucket_key`;

  return c.json({ ok: true, deletedNotes: deletedNotes.length, deletedRateLimitBuckets: deletedBuckets.length });
});
