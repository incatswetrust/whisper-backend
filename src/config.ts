function int(name: string, fallback: number): number {
  const raw = process.env[name];
  if (!raw) return fallback;
  const n = Number.parseInt(raw, 10);
  return Number.isFinite(n) && n > 0 ? n : fallback;
}

export const config = {
  port: int('PORT', 8787),
  // comma-separated list of allowed browser origins for CORS
  frontendOrigins: (process.env.FRONTEND_ORIGIN ?? 'http://localhost:5173').split(',').map((s) => s.trim()),
  // trust X-Forwarded-For (only enable behind a reverse proxy you control).
  // Vercel always sets this env var and its edge is a trustworthy first
  // hop, so it's on by default there.
  trustProxy: process.env.TRUST_PROXY === 'true' || Boolean(process.env.VERCEL),
  // Vercel serverless functions cap request/response bodies at ~4.5MB
  // (Hobby plan); stay under that with headroom. Raise via env if you're
  // self-hosting instead of deploying to Vercel.
  maxItemBytes: int('MAX_ITEM_BYTES', 4 * 1024 * 1024),
  defaultTtlMinutes: int('DEFAULT_TTL_MINUTES', 24 * 60), // fallback expiry if no ttl/views given
  // Rate limiting (see src/rateLimit.ts) — deliberately generous defaults,
  // this only needs to stop trivial spam/brute-forcing, not throttle
  // legitimate bursty use.
  rateLimitPostMax: int('RATE_LIMIT_POST_MAX', 20),
  rateLimitPostWindowMs: int('RATE_LIMIT_POST_WINDOW_MS', 60_000),
  rateLimitGetMax: int('RATE_LIMIT_GET_MAX', 60),
  rateLimitGetWindowMs: int('RATE_LIMIT_GET_WINDOW_MS', 60_000),
  // Tighter, per-note-id bucket specifically to slow password brute-forcing
  // against one note, on top of the general per-IP GET limiter above.
  rateLimitGetNoteMax: int('RATE_LIMIT_GET_NOTE_MAX', 10),
  rateLimitGetNoteWindowMs: int('RATE_LIMIT_GET_NOTE_WINDOW_MS', 60_000)
};
