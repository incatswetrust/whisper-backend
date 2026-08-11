import { Hono } from 'hono';
import { handle } from 'hono/vercel';
import { app } from '../src/app.js';

// Node.js runtime, not Edge: password hashing uses node:crypto's scryptSync,
// which Edge's Web Crypto subset doesn't provide.
export const config = { runtime: 'nodejs' };

// Vercel functions can only live (and be addressed) under /api, but the
// public API is served from api.whisper.beer with no /api prefix — the
// vercel.json rewrite sends every public path here as /api/<path>, so mount
// the app under /api here (and only here) rather than baking that prefix
// into the routes themselves.
const vercelApp = new Hono().route('/api', app);

export default handle(vercelApp);
