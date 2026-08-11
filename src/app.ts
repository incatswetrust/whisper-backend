import { Hono } from 'hono';
import { cors } from 'hono/cors';
import { config } from './config.js';
import { notes } from './routes/notes.js';
import { store } from './store.js';

export const app = new Hono();

app.use(
  '/api/*',
  cors({
    origin: config.frontendOrigins,
    allowHeaders: ['content-type', 'x-password', 'x-views', 'x-ttl-minutes', 'x-allowed-ip', 'x-filename', 'x-encrypted'],
    exposeHeaders: ['x-views-remaining', 'x-alg', 'x-iv', 'x-auth-tag', 'x-salt', 'x-has-password'],
    allowMethods: ['GET', 'POST']
  })
);

app.get('/api/health', async (c) => c.json(await store.stats()));
app.route('/api/notes', notes);
