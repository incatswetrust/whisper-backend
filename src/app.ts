import { Hono } from 'hono';
import { cors } from 'hono/cors';
import { config } from './config.js';
import { notes } from './routes/notes.js';
import { store } from './store.js';

export const app = new Hono();

// Burn-after-read notes must never be replayed from a cache — browsers,
// CDNs, and proxies all default to caching bare GETs otherwise.
app.use('*', async (c, next) => {
  await next();
  c.header('cache-control', 'no-store');
});

app.use(
  '*',
  cors({
    origin: config.frontendOrigins,
    allowHeaders: ['content-type', 'x-password', 'x-views', 'x-ttl-minutes', 'x-allowed-ip', 'x-filename', 'x-encrypted'],
    exposeHeaders: [
      'x-views-remaining',
      'x-alg',
      'x-iv',
      'x-auth-tag',
      'x-salt',
      'x-has-password',
      'content-disposition'
    ],
    allowMethods: ['GET', 'POST']
  })
);

app.get('/health', async (c) => c.json(await store.stats()));
app.route('/notes', notes);

// Vercel's zero-config Hono detection requires a default export.
export default app;
